#![forbid(unsafe_code)]

use storage_sqlcipher_fault_vfs::{
    RegistrationError, validate_null_callback_boundaries, validate_optional_service_forwarding,
};

#[test]
fn null_callback_inputs_fail_closed_without_dereferencing_them() {
    assert_eq!(
        RegistrationError::Rejected.to_string(),
        "named fault VFS registration rejected"
    );
    validate_null_callback_boundaries().expect("every null callback boundary fails closed");
}

#[test]
fn registered_vfs_forwards_optional_services_to_the_captured_default() {
    validate_optional_service_forwarding().expect("registered VFS must forward optional services");
}
