use std::{
    ffi::{CStr, CString, c_char},
    ptr,
};

use storage_sqlcipher_fault_vfs::{
    RegistrationError, VFS_NAME, register, validate_null_callback_boundaries,
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
    register().expect("register named delegator");
    let name = CString::new(VFS_NAME).expect("closed VFS name");

    // SAFETY: registration retains the named VFS for process lifetime. Every
    // callback below receives the exact registered pointer plus initialized
    // scalar/output arguments matching SQLite's public VFS ABI.
    unsafe {
        let vfs = libsqlite3_sys::sqlite3_vfs_find(name.as_ptr());
        assert!(!vfs.is_null(), "registered VFS must be discoverable");

        let mut randomness = [0_i8; 32];
        let generated = (*vfs).xRandomness.expect("wrapper randomness callback")(
            vfs,
            32,
            randomness.as_mut_ptr(),
        );
        assert!(generated > 0);

        let slept = (*vfs).xSleep.expect("wrapper sleep callback")(vfs, 0);
        assert!(slept >= 0);

        let mut julian_day = 0.0;
        assert_eq!(
            (*vfs).xCurrentTime.expect("wrapper current-time callback")(vfs, &mut julian_day),
            libsqlite3_sys::SQLITE_OK
        );
        assert!(julian_day > 0.0);

        let mut julian_millis = 0_i64;
        assert_eq!(
            (*vfs)
                .xCurrentTimeInt64
                .expect("wrapper integer-time callback")(vfs, &mut julian_millis),
            libsqlite3_sys::SQLITE_OK
        );
        assert!(julian_millis > 0);

        let mut last_error = [0_i8; 256];
        let _ = (*vfs).xGetLastError.expect("wrapper last-error callback")(
            vfs,
            i32::try_from(last_error.len()).expect("bounded error buffer"),
            last_error.as_mut_ptr(),
        );

        let first_system_call =
            (*vfs)
                .xNextSystemCall
                .expect("wrapper system-call enumeration")(vfs, ptr::null());
        if !first_system_call.is_null() {
            assert!(!CStr::from_ptr(first_system_call).to_bytes().is_empty());
            let call =
                (*vfs).xGetSystemCall.expect("wrapper system-call lookup")(vfs, first_system_call);
            assert!(call.is_some());
            assert_eq!(
                (*vfs)
                    .xSetSystemCall
                    .expect("wrapper system-call replacement")(
                    vfs, first_system_call, call,
                ),
                libsqlite3_sys::SQLITE_OK
            );
        }

        let missing_library =
            CString::new("session-chat-vfs-missing-library").expect("static missing-library name");
        let handle =
            (*vfs).xDlOpen.expect("wrapper loader callback")(vfs, missing_library.as_ptr());
        assert!(handle.is_null());
        let mut loader_error = [0_i8; 256];
        (*vfs).xDlError.expect("wrapper loader-error callback")(
            vfs,
            i32::try_from(loader_error.len()).expect("bounded loader-error buffer"),
            loader_error.as_mut_ptr().cast::<c_char>(),
        );
    }
}
