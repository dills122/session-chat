use mls_rs::storage_provider::in_memory::{InMemoryGroupStateStorage, InMemoryKeyPackageStorage};
use mls_rs_core::group::GroupStateStorage;
use session_crypto_mls::{
    SessionGroupId, create_client_with_storage, create_key_package_validator,
};

const NOW: u64 = 1_900_000_000;

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
