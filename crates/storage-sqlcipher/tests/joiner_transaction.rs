use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use mls_rs_core::group::{EpochRecord, GroupState, GroupStateStorage};
use session_crypto_mls::{
    SessionGroupId, create_client, create_client_with_storage, create_key_package_validator,
};
use storage_sqlcipher::{JoinerTransaction, PersistenceFault, SqlCipherStorage, VaultKey};
use zeroize::Zeroizing;

const NOW: u64 = 1_900_000_000;

use test_private_dir::TestDatabase;

#[derive(Clone)]
struct ProbingGroupStorage {
    storage: SqlCipherStorage,
    interleaved_access_rejected: Arc<AtomicBool>,
}

impl GroupStateStorage for ProbingGroupStorage {
    type Error = storage_sqlcipher::StoreError;

    fn state(&self, group_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        self.storage.state(group_id)
    }

    fn epoch(
        &self,
        group_id: &[u8],
        epoch_id: u64,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        self.storage.epoch(group_id, epoch_id)
    }

    fn write(
        &mut self,
        state: GroupState,
        epoch_inserts: Vec<EpochRecord>,
        epoch_updates: Vec<EpochRecord>,
    ) -> Result<(), Self::Error> {
        let group_id = state.id.clone();
        self.storage.write(state, epoch_inserts, epoch_updates)?;
        let probe = self.storage.clone();
        self.interleaved_access_rejected.store(
            probe.state(&group_id).is_err()
                && probe.max_epoch_id(&group_id).is_err()
                && probe.schema_version().is_err()
                && probe
                    .seed_reservation([0x51; 16], [0x52; 64], [0x53; 16], NOW + 300, NOW)
                    .is_err(),
            Ordering::SeqCst,
        );
        Ok(())
    }

    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        self.storage.max_epoch_id(group_id)
    }
}

#[test]
fn actual_joiner_write_atomically_persists_group_and_deletes_one_time_key_package() {
    let database = TestDatabase::new("database");
    let storage = SqlCipherStorage::create(
        &database.0,
        VaultKey::new([21; 32]).expect("nonzero test key"),
    )
    .expect("storage created");
    let interleaved_access_rejected = Arc::new(AtomicBool::new(false));
    let bob = create_client_with_storage(
        ProbingGroupStorage {
            storage: storage.clone(),
            interleaved_access_rejected: Arc::clone(&interleaved_access_rejected),
        },
        storage.clone(),
    )
    .expect("Bob client");
    let bob_key_package = bob.generate_key_package(NOW).expect("Bob KeyPackage");
    let validated = create_key_package_validator()
        .validate_key_package(bob_key_package.as_bytes(), NOW)
        .expect("validated KeyPackage");
    let key_package_reference = *validated.key_package_reference();
    assert!(
        storage
            .key_package_exists(&key_package_reference)
            .expect("KeyPackage lookup")
    );

    let alice = create_client().expect("Alice client");
    let mut alice_group = alice
        .create_group(SessionGroupId::new([31; 32]).expect("group id"), NOW)
        .expect("Alice group");
    let welcome = alice_group
        .prepare_add(validated, NOW)
        .expect("prepared Add")
        .apply()
        .expect("applied Add")
        .into_welcome();
    let mut bob_group = bob.join_group(welcome, NOW).expect("Bob joins");

    let failed = JoinerTransaction::new([41; 16], *bob_group.group_id(), key_package_reference)
        .expect("bounded joiner transaction");
    storage
        .stage_joiner(failed, PersistenceFault::BeforeCommit)
        .expect("joiner transaction staged");
    assert!(bob_group.write_to_storage().is_err());
    assert!(interleaved_access_rejected.load(Ordering::SeqCst));
    assert!(
        storage
            .state(bob_group.group_id())
            .expect("group lookup")
            .is_none()
    );
    assert!(
        storage
            .key_package_exists(&key_package_reference)
            .expect("KeyPackage lookup")
    );
    assert!(
        storage
            .recover_joiner(&[41; 16])
            .expect("recovery lookup")
            .is_none()
    );

    let retry = JoinerTransaction::new([41; 16], *bob_group.group_id(), key_package_reference)
        .expect("bounded retry");
    storage
        .stage_joiner(retry, PersistenceFault::AfterCommit)
        .expect("retry staged");
    assert!(bob_group.write_to_storage().is_err());

    assert!(
        storage
            .state(bob_group.group_id())
            .expect("group lookup")
            .is_some()
    );
    assert!(
        !storage
            .key_package_exists(&key_package_reference)
            .expect("KeyPackage lookup")
    );
    let recovered = storage
        .recover_joiner(&[41; 16])
        .expect("recovery lookup")
        .expect("joiner transaction committed");
    assert_eq!(recovered.group_id, *bob_group.group_id());

    let exact_recovery =
        JoinerTransaction::new([41; 16], *bob_group.group_id(), key_package_reference)
            .expect("bounded recovery");
    storage
        .stage_joiner(exact_recovery, PersistenceFault::None)
        .expect("recovery staged");
    bob_group
        .write_to_storage()
        .expect("committed join recovered idempotently");

    drop(bob_group);
    drop(bob);
    drop(storage);
    let reopened = SqlCipherStorage::open(
        &database.0,
        VaultKey::new([21; 32]).expect("nonzero test key"),
    )
    .expect("store reopens");
    assert_eq!(
        reopened
            .recover_joiner(&[41; 16])
            .expect("recovery after reopen"),
        Some(recovered)
    );
    assert!(
        !reopened
            .key_package_exists(&key_package_reference)
            .expect("KeyPackage lookup after reopen")
    );
}
