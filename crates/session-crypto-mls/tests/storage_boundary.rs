use std::sync::{Arc, Mutex};

use mls_rs::storage_provider::in_memory::{InMemoryGroupStateStorage, InMemoryKeyPackageStorage};
use mls_rs_core::group::GroupStateStorage;
use session_crypto_mls::{
    DurableClientIdentityStorage, IncomingMessage, MlsWireMessage, SessionGroupId,
    create_client_with_storage, create_durable_client_with_storage, create_key_package_validator,
    load_durable_client_with_storage,
};
use zeroize::Zeroizing;

const NOW: u64 = 1_900_000_000;

#[derive(Clone, Default)]
struct IdentityStore(Arc<Mutex<Option<Vec<u8>>>>);

impl DurableClientIdentityStorage for IdentityStore {
    type Error = ();

    fn load_client_identity(&self) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        Ok(self
            .0
            .lock()
            .map_err(|_| ())?
            .as_ref()
            .map(|bytes| Zeroizing::new(bytes.clone())))
    }

    fn insert_client_identity(&self, encoded: &[u8]) -> Result<(), Self::Error> {
        let mut retained = self.0.lock().map_err(|_| ())?;
        if retained.is_some() {
            return Err(());
        }
        *retained = Some(encoded.to_vec());
        Ok(())
    }
}

fn assert_identity_rejected(encoded: Vec<u8>) {
    let store = IdentityStore::default();
    store
        .insert_client_identity(&encoded)
        .expect("hostile identity fixture inserted");
    assert!(
        load_durable_client_with_storage(
            InMemoryGroupStateStorage::default(),
            InMemoryKeyPackageStorage::default(),
            store,
        )
        .is_err()
    );
}

#[test]
fn configured_provider_receives_real_group_writes_and_joiner_key_package_deletion() {
    let alice_groups = InMemoryGroupStateStorage::default();
    let alice_key_packages = InMemoryKeyPackageStorage::default();
    let alice =
        create_client_with_storage(alice_groups.clone(), alice_key_packages).expect("Alice client");
    let mut alice_group = alice
        .create_group(SessionGroupId::new([1; 32]).expect("group id"), NOW)
        .expect("Alice group");

    let bob_groups = InMemoryGroupStateStorage::default();
    let bob_key_packages = InMemoryKeyPackageStorage::default();
    let bob = create_client_with_storage(bob_groups.clone(), bob_key_packages.clone())
        .expect("Bob client");
    let bob_key_package = bob.generate_key_package(NOW).expect("Bob KeyPackage");
    let validator = create_key_package_validator();
    let validated = validator
        .validate_key_package(bob_key_package.as_bytes(), NOW)
        .expect("validated KeyPackage");
    let key_package_reference = *validated.key_package_reference();
    assert!(bob_key_packages.get(&key_package_reference).is_some());

    let addition = alice_group
        .prepare_add(validated, NOW)
        .expect("prepared Add")
        .apply()
        .expect("applied Add");
    alice_group
        .write_to_storage()
        .expect("inviter group persisted");
    assert!(
        alice_groups
            .state(alice_group.group_id())
            .expect("inviter state lookup")
            .is_some()
    );

    let mut bob_group = bob
        .join_group(addition.into_welcome(), NOW)
        .expect("Bob joins");
    assert!(
        bob_groups
            .state(bob_group.group_id())
            .expect("pre-write group lookup")
            .is_none()
    );
    assert!(bob_key_packages.get(&key_package_reference).is_some());

    bob_group
        .write_to_storage()
        .expect("joiner group and KeyPackage deletion persisted");
    assert!(
        bob_groups
            .state(bob_group.group_id())
            .expect("joiner state lookup")
            .is_some()
    );
    assert!(bob_key_packages.get(&key_package_reference).is_none());
}

#[test]
fn durable_identity_reloads_the_same_member_and_rejects_fresh_or_malformed_identity() {
    let alice_groups = InMemoryGroupStateStorage::default();
    let alice_key_packages = InMemoryKeyPackageStorage::default();
    let alice_identity = IdentityStore::default();
    let alice = create_durable_client_with_storage(
        alice_groups.clone(),
        alice_key_packages.clone(),
        alice_identity.clone(),
    )
    .expect("durable Alice client");
    let original_credential = *alice.credential_identity().as_bytes();
    let valid_identity = alice_identity
        .load_client_identity()
        .expect("identity lookup")
        .expect("identity retained");
    let group_id = SessionGroupId::new([0x51; 32]).expect("group id");
    let mut alice_group = alice.create_group(group_id, NOW).expect("Alice group");

    let bob = create_client_with_storage(
        InMemoryGroupStateStorage::default(),
        InMemoryKeyPackageStorage::default(),
    )
    .expect("Bob client");
    let bob_key_package = bob.generate_key_package(NOW).expect("Bob KeyPackage");
    let validated = create_key_package_validator()
        .validate_key_package(bob_key_package.as_bytes(), NOW)
        .expect("validated KeyPackage");
    let welcome = alice_group
        .prepare_add(validated, NOW)
        .expect("prepared Add")
        .apply()
        .expect("applied Add")
        .into_welcome();
    let mut bob_group = bob.join_group(welcome, NOW).expect("Bob joins");
    alice_group.write_to_storage().expect("Alice state stored");
    drop(alice_group);
    drop(alice);

    let reloaded = load_durable_client_with_storage(
        alice_groups.clone(),
        alice_key_packages.clone(),
        alice_identity.clone(),
    )
    .expect("Alice identity reloaded");
    assert_eq!(
        reloaded.credential_identity().as_bytes(),
        &original_credential
    );
    let mut reloaded_group = reloaded.load_group(group_id).expect("Alice group reloaded");
    assert_eq!(reloaded_group.epoch(), 1);
    assert_eq!(reloaded_group.member_count(), 2);
    let message = reloaded_group
        .encrypt_application_message(b"after restart")
        .expect("restart message");
    assert_eq!(
        bob_group
            .process_message(
                MlsWireMessage::from_bytes(message.as_bytes()).expect("bounded message")
            )
            .expect("Bob processes restart message"),
        IncomingMessage::Application(b"after restart".to_vec())
    );

    let fresh = create_client_with_storage(alice_groups, alice_key_packages)
        .expect("fresh client using old group store");
    assert!(fresh.load_group(group_id).is_err());
    assert!(
        create_durable_client_with_storage(
            InMemoryGroupStateStorage::default(),
            InMemoryKeyPackageStorage::default(),
            alice_identity,
        )
        .is_err()
    );

    let missing = IdentityStore::default();
    assert!(
        load_durable_client_with_storage(
            InMemoryGroupStateStorage::default(),
            InMemoryKeyPackageStorage::default(),
            missing,
        )
        .is_err()
    );
    let malformed = IdentityStore::default();
    malformed
        .insert_client_identity(&[0xff; 7])
        .expect("malformed fixture inserted");
    assert!(
        load_durable_client_with_storage(
            InMemoryGroupStateStorage::default(),
            InMemoryKeyPackageStorage::default(),
            malformed,
        )
        .is_err()
    );

    for index in [0, 8, 9, 10, 11, 12, 45, 77] {
        let mut altered = valid_identity.to_vec();
        altered[index] ^= 0xff;
        assert_identity_rejected(altered);
    }
    let mut zero_credential = valid_identity.to_vec();
    zero_credential[13..45].fill(0);
    assert_identity_rejected(zero_credential);
    assert_identity_rejected(valid_identity[..valid_identity.len() - 1].to_vec());
}
