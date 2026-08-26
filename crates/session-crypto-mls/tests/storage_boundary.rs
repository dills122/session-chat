use std::sync::{Arc, Mutex};

use mls_rs::storage_provider::in_memory::{InMemoryGroupStateStorage, InMemoryKeyPackageStorage};
use mls_rs_core::group::GroupStateStorage;
use session_crypto_mls::{
    DURABLE_CLIENT_IDENTITY_BYTES, DurableClientIdentityRecord, DurableClientIdentityStorage,
    IncomingMessage, MlsWireMessage, SessionGroupId, create_client_with_storage,
    create_durable_client_with_storage, create_key_package_validator,
    load_durable_client_with_storage,
};

const NOW: u64 = 1_900_000_000;
const IDENTITY_V1_CREDENTIAL: [u8; 32] = [0x42; 32];
const IDENTITY_V1_SIGNING_PUBLIC_KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
// Fixed durable identity-v1 record using RFC 8032 test vector 1 Ed25519
// material. These are public test-only bytes, never a production identity.
const IDENTITY_V1_HEX: &str = concat!(
    "53434d4c53494431", // SCMLSID1
    "01",               // record version 1
    "01",               // MLS 1.0
    "0001",             // CURVE25519_AES128
    "01",               // pinned AWS-LC representation
    "4242424242424242424242424242424242424242424242424242424242424242",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
);

#[derive(Default)]
struct StoredIdentity {
    group_id: [u8; 32],
    encoded: Vec<u8>,
}

#[derive(Clone, Default)]
struct IdentityStore(Arc<Mutex<Option<StoredIdentity>>>);

impl IdentityStore {
    fn insert_raw(&self, group_id: SessionGroupId, encoded: Vec<u8>) -> Result<(), ()> {
        let mut retained = self.0.lock().map_err(|_| ())?;
        if retained.is_some() {
            return Err(());
        }
        *retained = Some(StoredIdentity {
            group_id: *group_id.as_bytes(),
            encoded,
        });
        Ok(())
    }

    fn raw_bytes(&self) -> Vec<u8> {
        self.0
            .lock()
            .expect("identity store lock")
            .as_ref()
            .expect("identity retained")
            .encoded
            .clone()
    }
}

impl DurableClientIdentityStorage for IdentityStore {
    type Error = ();

    fn load_client_identity(
        &self,
        group_id: &SessionGroupId,
    ) -> Result<Option<DurableClientIdentityRecord>, Self::Error> {
        let retained = self.0.lock().map_err(|_| ())?;
        let Some(retained) = retained.as_ref() else {
            return Ok(None);
        };
        if retained.group_id != *group_id.as_bytes() {
            return Err(());
        }
        DurableClientIdentityRecord::from_storage_bytes(retained.encoded.clone())
            .map(Some)
            .map_err(|_| ())
    }

    fn insert_client_identity(
        &self,
        group_id: &SessionGroupId,
        encoded: DurableClientIdentityRecord,
    ) -> Result<(), Self::Error> {
        self.insert_raw(*group_id, encoded.into_storage_bytes().to_vec())
    }
}

fn assert_identity_rejected(encoded: Vec<u8>) {
    let store = IdentityStore::default();
    let group_id = SessionGroupId::new([0x51; 32]).expect("group id");
    store
        .insert_raw(group_id, encoded)
        .expect("hostile identity fixture inserted");
    assert!(
        load_durable_client_with_storage(
            group_id,
            InMemoryGroupStateStorage::default(),
            InMemoryKeyPackageStorage::default(),
            store,
        )
        .is_err()
    );
}

fn decode_hex(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2));
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("fixture is valid hex"))
        .collect()
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
fn frozen_identity_v1_fixture_loads_the_expected_credential_and_signer() {
    let encoded = decode_hex(IDENTITY_V1_HEX);
    assert_eq!(encoded.len(), DURABLE_CLIENT_IDENTITY_BYTES);
    let group_id = SessionGroupId::new([0x41; 32]).expect("group id");
    let identity = IdentityStore::default();
    identity
        .insert_client_identity(
            &group_id,
            DurableClientIdentityRecord::from_storage_bytes(encoded)
                .expect("fixed identity-v1 record"),
        )
        .expect("fixed identity-v1 fixture inserted");

    let client = load_durable_client_with_storage(
        group_id,
        InMemoryGroupStateStorage::default(),
        InMemoryKeyPackageStorage::default(),
        identity,
    )
    .expect("fixed identity-v1 fixture loads");
    assert_eq!(
        client.credential_identity().as_bytes(),
        &IDENTITY_V1_CREDENTIAL
    );

    let key_package = client
        .generate_key_package(NOW)
        .expect("fixed signer creates KeyPackage");
    let validated = create_key_package_validator()
        .validate_key_package(key_package.as_bytes(), NOW)
        .expect("fixed signer creates a valid KeyPackage");
    assert_eq!(validated.credential_identity(), &IDENTITY_V1_CREDENTIAL);
    assert_eq!(
        validated.leaf_signature_key(),
        &IDENTITY_V1_SIGNING_PUBLIC_KEY
    );
}

#[test]
fn durable_identity_reloads_the_same_member_and_rejects_fresh_or_malformed_identity() {
    let alice_groups = InMemoryGroupStateStorage::default();
    let alice_key_packages = InMemoryKeyPackageStorage::default();
    let alice_identity = IdentityStore::default();
    let group_id = SessionGroupId::new([0x51; 32]).expect("group id");
    let foreign_group_id = SessionGroupId::new([0x52; 32]).expect("foreign group id");
    let alice = create_durable_client_with_storage(
        group_id,
        alice_groups.clone(),
        alice_key_packages.clone(),
        alice_identity.clone(),
    )
    .expect("durable Alice client");
    let original_credential = *alice.credential_identity().as_bytes();
    let valid_identity = alice_identity.raw_bytes();
    let mut alice_group = alice.create_group(group_id, NOW).expect("Alice group");
    assert!(alice.create_group(foreign_group_id, NOW).is_err());
    assert!(
        load_durable_client_with_storage(
            foreign_group_id,
            alice_groups.clone(),
            alice_key_packages.clone(),
            alice_identity.clone(),
        )
        .is_err()
    );

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
        group_id,
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
            group_id,
            InMemoryGroupStateStorage::default(),
            InMemoryKeyPackageStorage::default(),
            alice_identity,
        )
        .is_err()
    );

    let missing = IdentityStore::default();
    assert!(
        load_durable_client_with_storage(
            group_id,
            InMemoryGroupStateStorage::default(),
            InMemoryKeyPackageStorage::default(),
            missing,
        )
        .is_err()
    );
    let malformed = IdentityStore::default();
    malformed
        .insert_raw(group_id, vec![0xff; 7])
        .expect("malformed fixture inserted");
    assert!(
        load_durable_client_with_storage(
            group_id,
            InMemoryGroupStateStorage::default(),
            InMemoryKeyPackageStorage::default(),
            malformed,
        )
        .is_err()
    );

    for index in [0, 8, 9, 10, 11, 12, 45, 77] {
        let mut altered = valid_identity.clone();
        altered[index] ^= 0xff;
        assert_identity_rejected(altered);
    }
    let mut zero_credential = valid_identity.clone();
    zero_credential[13..45].fill(0);
    assert_identity_rejected(zero_credential);
    assert_identity_rejected(valid_identity[..valid_identity.len() - 1].to_vec());
}
