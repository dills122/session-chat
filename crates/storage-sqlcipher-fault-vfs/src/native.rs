//! Minimal SQLite ABI delegator.
//!
//! All unsafe code in this crate is isolated here. SQLite allocates each file
//! object using the registered `szOsFile`; the prefix below stores only a role
//! tag and the default VFS file object follows at an aligned offset. Every
//! callback validates pointers/function slots before delegation. The leaked VFS
//! allocation has process lifetime because SQLite retains the registered pointer.

#![deny(unsafe_op_in_unsafe_fn)]

use std::{
    ffi::{CStr, c_char, c_int, c_void},
    fmt,
    mem::{align_of, size_of},
    ptr,
    sync::OnceLock,
};

use libsqlite3_sys as ffi;

use crate::{
    FileRole, Operation, VFS_NAME,
    controller::{Decision, RoleEvidence, observe},
};

const VFS_NAME_C: &[u8] = b"session-chat-storage-fault-v1\0";
const SQLITE_OPEN_ROLE_MASK: c_int = ffi::SQLITE_OPEN_MAIN_DB
    | ffi::SQLITE_OPEN_TEMP_DB
    | ffi::SQLITE_OPEN_TRANSIENT_DB
    | ffi::SQLITE_OPEN_MAIN_JOURNAL
    | ffi::SQLITE_OPEN_TEMP_JOURNAL
    | ffi::SQLITE_OPEN_SUBJOURNAL
    | ffi::SQLITE_OPEN_WAL;

#[repr(C)]
struct WrappedFile {
    base: ffi::sqlite3_file,
    role: c_int,
    evidence: c_int,
}

const REAL_FILE_OFFSET: usize = align_up(size_of::<WrappedFile>(), align_of::<usize>());

const fn align_up(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

/// Stable process-local identity of SQLite's selected default VFS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DefaultVfsIdentity {
    address: usize,
}

/// Coarse registration failure with no VFS name or path from runtime input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationError {
    /// SQLite initialization, default lookup, sizing, or registration failed.
    Rejected,
}

impl fmt::Display for RegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("named fault VFS registration rejected")
    }
}

impl std::error::Error for RegistrationError {}

/// Returns SQLite's current default VFS identity without changing it.
pub fn default_vfs_identity() -> Result<DefaultVfsIdentity, RegistrationError> {
    // SAFETY: SQLite initialization and a null-name lookup are process-global C
    // APIs. No Rust reference is created from the returned pointer.
    unsafe {
        if ffi::sqlite3_initialize() != ffi::SQLITE_OK {
            return Err(RegistrationError::Rejected);
        }
        let default = ffi::sqlite3_vfs_find(ptr::null());
        if default.is_null() {
            return Err(RegistrationError::Rejected);
        }
        Ok(DefaultVfsIdentity {
            address: default as usize,
        })
    }
}

/// Registers the closed named delegator with SQLite's make-default flag off.
pub fn register() -> Result<(), RegistrationError> {
    static REGISTRATION: OnceLock<Result<(), RegistrationError>> = OnceLock::new();
    *REGISTRATION.get_or_init(|| {
        // SAFETY: `register_inner` creates a process-lifetime VFS allocation and
        // registers it exactly once under this `OnceLock`.
        unsafe { register_inner() }
    })
}

unsafe fn register_inner() -> Result<(), RegistrationError> {
    // SAFETY: process-global SQLite initialization has no Rust aliasing contract.
    if unsafe { ffi::sqlite3_initialize() } != ffi::SQLITE_OK {
        return Err(RegistrationError::Rejected);
    }
    // SAFETY: null requests the current default VFS per SQLite's API.
    let default = unsafe { ffi::sqlite3_vfs_find(ptr::null()) };
    if default.is_null() {
        return Err(RegistrationError::Rejected);
    }
    // SAFETY: `default` was returned non-null by SQLite and remains registered.
    let default_size = unsafe { (*default).szOsFile };
    let wrapped_size = usize::try_from(default_size)
        .ok()
        .and_then(|size| size.checked_add(REAL_FILE_OFFSET))
        .and_then(|size| c_int::try_from(size).ok())
        .ok_or(RegistrationError::Rejected)?;
    // SAFETY: the SQLite-owned VFS record is Copy ABI data. Function callbacks
    // are replaced below so none receive the wrong VFS pointer.
    let mut delegated = unsafe { ptr::read(default) };
    delegated.iVersion = delegated.iVersion.clamp(1, 3);
    delegated.szOsFile = wrapped_size;
    delegated.pNext = ptr::null_mut();
    delegated.zName = VFS_NAME_C.as_ptr().cast();
    delegated.pAppData = default.cast();
    delegated.xOpen = Some(vfs_open);
    delegated.xDelete = Some(vfs_delete);
    delegated.xAccess = Some(vfs_access);
    delegated.xFullPathname = Some(vfs_full_pathname);
    delegated.xDlOpen = Some(vfs_dl_open);
    delegated.xDlError = Some(vfs_dl_error);
    delegated.xDlSym = Some(vfs_dl_sym);
    delegated.xDlClose = Some(vfs_dl_close);
    delegated.xRandomness = Some(vfs_randomness);
    delegated.xSleep = Some(vfs_sleep);
    delegated.xCurrentTime = Some(vfs_current_time);
    delegated.xGetLastError = Some(vfs_get_last_error);
    delegated.xCurrentTimeInt64 = Some(vfs_current_time_int64);
    delegated.xSetSystemCall = Some(vfs_set_system_call);
    delegated.xGetSystemCall = Some(vfs_get_system_call);
    delegated.xNextSystemCall = Some(vfs_next_system_call);

    let registered = Box::into_raw(Box::new(delegated));
    // SAFETY: `registered` points to a fully initialized process-lifetime VFS;
    // `0` explicitly disables SQLite's make-default behavior.
    let result = unsafe { ffi::sqlite3_vfs_register(registered, 0) };
    if result != ffi::SQLITE_OK {
        // SAFETY: failed registration did not transfer pointer retention to SQLite.
        unsafe { drop(Box::from_raw(registered)) };
        return Err(RegistrationError::Rejected);
    }
    debug_assert_eq!(VFS_NAME, "session-chat-storage-fault-v1");
    Ok(())
}

unsafe fn delegated_vfs(vfs: *mut ffi::sqlite3_vfs) -> Result<*mut ffi::sqlite3_vfs, c_int> {
    if vfs.is_null() {
        return Err(ffi::SQLITE_IOERR);
    }
    // SAFETY: SQLite supplies the registered VFS pointer to its callbacks.
    let delegated = unsafe { (*vfs).pAppData.cast::<ffi::sqlite3_vfs>() };
    if delegated.is_null() {
        Err(ffi::SQLITE_IOERR)
    } else {
        Ok(delegated)
    }
}

unsafe fn real_file(file: *mut ffi::sqlite3_file) -> Result<*mut ffi::sqlite3_file, c_int> {
    if file.is_null() {
        return Err(ffi::SQLITE_IOERR);
    }
    // SAFETY: SQLite allocated `szOsFile` bytes for our registered layout.
    Ok(unsafe { file.cast::<u8>().add(REAL_FILE_OFFSET).cast() })
}

unsafe fn wrapped_metadata(
    file: *mut ffi::sqlite3_file,
) -> Result<(FileRole, RoleEvidence), c_int> {
    if file.is_null() {
        return Err(ffi::SQLITE_IOERR);
    }
    // SAFETY: every file passed to our I/O methods was initialized by `vfs_open`.
    let wrapped = unsafe { &*file.cast::<WrappedFile>() };
    Ok((
        FileRole::from_index(wrapped.role),
        RoleEvidence::from_index(wrapped.evidence),
    ))
}

fn classify_open(flags: c_int) -> (FileRole, RoleEvidence) {
    let role_bits = flags & SQLITE_OPEN_ROLE_MASK;
    if role_bits == ffi::SQLITE_OPEN_MAIN_DB {
        (FileRole::MainDatabase, RoleEvidence::MainFlag)
    } else if role_bits == ffi::SQLITE_OPEN_MAIN_JOURNAL {
        (FileRole::RollbackJournal, RoleEvidence::JournalFlag)
    } else if role_bits == ffi::SQLITE_OPEN_WAL {
        (FileRole::Wal, RoleEvidence::WalFlag)
    } else if matches!(
        role_bits,
        ffi::SQLITE_OPEN_TEMP_DB
            | ffi::SQLITE_OPEN_TRANSIENT_DB
            | ffi::SQLITE_OPEN_TEMP_JOURNAL
            | ffi::SQLITE_OPEN_SUBJOURNAL
    ) {
        (FileRole::Temporary, RoleEvidence::TemporaryFlag)
    } else {
        (FileRole::Unknown, RoleEvidence::Unknown)
    }
}

unsafe fn classify_delete(name: *const c_char) -> (FileRole, RoleEvidence) {
    if name.is_null() {
        return (FileRole::Temporary, RoleEvidence::TemporaryName);
    }
    // SAFETY: SQLite guarantees callback filenames are NUL-terminated strings.
    let bytes = unsafe { CStr::from_ptr(name) }.to_bytes();
    if bytes.ends_with(b"-journal") {
        (FileRole::RollbackJournal, RoleEvidence::JournalName)
    } else if bytes.ends_with(b"-wal") {
        (FileRole::Wal, RoleEvidence::WalName)
    } else if bytes.ends_with(b"-shm") {
        (FileRole::SharedMemory, RoleEvidence::SharedMemoryName)
    } else {
        (FileRole::Temporary, RoleEvidence::TemporaryName)
    }
}

fn apply_decision(decision: Decision, fallback: c_int) -> Result<(), c_int> {
    match decision {
        Decision::Delegate => Ok(()),
        Decision::Return(code) => Err(code),
        Decision::Pause(gate) => gate.block().map_err(|_| fallback),
    }
}

unsafe fn before_io(
    file: *mut ffi::sqlite3_file,
    operation: Operation,
) -> Result<*mut ffi::sqlite3_file, c_int> {
    // SAFETY: the callback's file pointer belongs to the registered wrapper.
    let (role, evidence) = unsafe { wrapped_metadata(file) }?;
    apply_decision(observe(role, evidence, operation), ffi::SQLITE_IOERR)?;
    // SAFETY: the same wrapper allocation contains the delegated file object.
    unsafe { real_file(file) }
}

unsafe fn before_shared_memory(
    file: *mut ffi::sqlite3_file,
) -> Result<*mut ffi::sqlite3_file, c_int> {
    apply_decision(
        observe(
            FileRole::SharedMemory,
            RoleEvidence::SharedMemoryCallback,
            Operation::SharedMemory,
        ),
        ffi::SQLITE_IOERR,
    )?;
    // SAFETY: the callback's file pointer belongs to the registered wrapper.
    unsafe { real_file(file) }
}

unsafe fn io_methods(
    file: *mut ffi::sqlite3_file,
) -> Result<*const ffi::sqlite3_io_methods, c_int> {
    if file.is_null() {
        return Err(ffi::SQLITE_IOERR);
    }
    // SAFETY: delegated xOpen initialized this sqlite3_file on success.
    let methods = unsafe { (*file).pMethods };
    if methods.is_null() {
        Err(ffi::SQLITE_IOERR)
    } else {
        Ok(methods)
    }
}

const fn io_method_table(version: c_int) -> ffi::sqlite3_io_methods {
    ffi::sqlite3_io_methods {
        iVersion: version,
        xClose: Some(io_close),
        xRead: Some(io_read),
        xWrite: Some(io_write),
        xTruncate: Some(io_truncate),
        xSync: Some(io_sync),
        xFileSize: Some(io_file_size),
        xLock: Some(io_lock),
        xUnlock: Some(io_unlock),
        xCheckReservedLock: Some(io_check_reserved_lock),
        xFileControl: Some(io_file_control),
        xSectorSize: Some(io_sector_size),
        xDeviceCharacteristics: Some(io_device_characteristics),
        xShmMap: Some(io_shm_map),
        xShmLock: Some(io_shm_lock),
        xShmBarrier: Some(io_shm_barrier),
        xShmUnmap: Some(io_shm_unmap),
        xFetch: Some(io_fetch),
        xUnfetch: Some(io_unfetch),
    }
}

static IO_METHODS_V1: ffi::sqlite3_io_methods = io_method_table(1);
static IO_METHODS_V2: ffi::sqlite3_io_methods = io_method_table(2);
static IO_METHODS_V3: ffi::sqlite3_io_methods = io_method_table(3);

/// SQLite xOpen boundary: initializes the wrapped prefix and delegates the real file.
unsafe extern "C" fn vfs_open(
    vfs: *mut ffi::sqlite3_vfs,
    name: ffi::sqlite3_filename,
    file: *mut ffi::sqlite3_file,
    flags: c_int,
    out_flags: *mut c_int,
) -> c_int {
    // SAFETY: callback pointers and buffers are supplied by SQLite for this VFS.
    let Ok(delegated) = (unsafe { delegated_vfs(vfs) }) else {
        return ffi::SQLITE_IOERR;
    };
    // SAFETY: `file` is SQLite's allocation of our advertised `szOsFile`.
    let Ok(real) = (unsafe { real_file(file) }) else {
        return ffi::SQLITE_IOERR;
    };
    // SAFETY: non-null delegated VFS came from SQLite's registry.
    let Some(open) = (unsafe { (*delegated).xOpen }) else {
        return ffi::SQLITE_IOERR;
    };
    // SAFETY: forward the exact SQLite arguments with the delegated file tail.
    let result = unsafe { open(delegated, name, real, flags, out_flags) };
    if result != ffi::SQLITE_OK {
        return result;
    }
    // SAFETY: successful delegated open must publish a non-null method table.
    if unsafe { (*real).pMethods.is_null() } {
        return ffi::SQLITE_IOERR;
    }
    let (role, evidence) = classify_open(flags);
    // SAFETY: successful delegated open published a readable method table.
    let delegated_version = unsafe { (*(*real).pMethods).iVersion };
    let wrapper_methods = match delegated_version {
        1 => &IO_METHODS_V1,
        2 => &IO_METHODS_V2,
        3.. => &IO_METHODS_V3,
        _ => {
            // SAFETY: the delegated open succeeded and supplied this live table.
            if let Some(close) = unsafe { (*(*real).pMethods).xClose } {
                // SAFETY: close receives its exact delegated file pointer.
                let _ = unsafe { close(real) };
            }
            return ffi::SQLITE_IOERR;
        }
    };
    // SAFETY: write initializes the complete wrapper prefix without forming a
    // reference to SQLite's previously uninitialized allocation.
    unsafe {
        ptr::write(
            file.cast::<WrappedFile>(),
            WrappedFile {
                base: ffi::sqlite3_file {
                    pMethods: wrapper_methods,
                },
                role: role as c_int,
                evidence: evidence.code(),
            },
        );
    }
    match apply_decision(observe(role, evidence, Operation::Open), ffi::SQLITE_IOERR) {
        Ok(()) => ffi::SQLITE_OK,
        Err(code) => {
            // SAFETY: the delegated file is open and owns its close callback.
            let methods = unsafe { (*real).pMethods };
            if !methods.is_null() {
                // SAFETY: method table was supplied by successful delegated xOpen.
                if let Some(close) = unsafe { (*methods).xClose } {
                    // SAFETY: close receives its exact delegated file pointer.
                    let _ = unsafe { close(real) };
                }
            }
            // SAFETY: prevent SQLite from calling methods on a rejected open.
            unsafe { (*file).pMethods = ptr::null() };
            code
        }
    }
}

/// SQLite xDelete boundary: classifies by closed suffix and delegates unchanged.
unsafe extern "C" fn vfs_delete(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    sync_dir: c_int,
) -> c_int {
    // SAFETY: SQLite supplies a valid optional filename at this boundary.
    let (role, evidence) = unsafe { classify_delete(name) };
    if let Err(code) = apply_decision(
        observe(role, evidence, Operation::Delete),
        ffi::SQLITE_IOERR_DELETE,
    ) {
        return code;
    }
    // SAFETY: delegate lookup and callback use SQLite-owned pointers unchanged.
    let Ok(delegated) = (unsafe { delegated_vfs(vfs) }) else {
        return ffi::SQLITE_IOERR_DELETE;
    };
    // SAFETY: delegated VFS pointer is registered and readable.
    let Some(delete) = (unsafe { (*delegated).xDelete }) else {
        return ffi::SQLITE_IOERR_DELETE;
    };
    // SAFETY: exact forwarding to the default VFS.
    unsafe { delete(delegated, name, sync_dir) }
}

/// SQLite xAccess boundary forwarded to the captured default VFS.
unsafe extern "C" fn vfs_access(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    flags: c_int,
    out: *mut c_int,
) -> c_int {
    // SAFETY: exact callback forwarding after a checked delegated lookup.
    let Ok(delegated) = (unsafe { delegated_vfs(vfs) }) else {
        return ffi::SQLITE_IOERR;
    };
    // SAFETY: delegated VFS pointer is registered and readable.
    let Some(callback) = (unsafe { (*delegated).xAccess }) else {
        return ffi::SQLITE_IOERR;
    };
    // SAFETY: SQLite owns all forwarded pointer arguments.
    unsafe { callback(delegated, name, flags, out) }
}

/// SQLite xFullPathname boundary forwarded to the captured default VFS.
unsafe extern "C" fn vfs_full_pathname(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    out_len: c_int,
    out: *mut c_char,
) -> c_int {
    // SAFETY: exact callback forwarding after a checked delegated lookup.
    let Ok(delegated) = (unsafe { delegated_vfs(vfs) }) else {
        return ffi::SQLITE_IOERR;
    };
    // SAFETY: delegated VFS pointer is registered and readable.
    let Some(callback) = (unsafe { (*delegated).xFullPathname }) else {
        return ffi::SQLITE_IOERR;
    };
    // SAFETY: SQLite owns all forwarded pointer arguments.
    unsafe { callback(delegated, name, out_len, out) }
}

/// SQLite dynamic-loader open boundary forwarded unchanged.
unsafe extern "C" fn vfs_dl_open(vfs: *mut ffi::sqlite3_vfs, name: *const c_char) -> *mut c_void {
    // SAFETY: exact callback forwarding after a checked delegated lookup.
    let Ok(delegated) = (unsafe { delegated_vfs(vfs) }) else {
        return ptr::null_mut();
    };
    // SAFETY: delegated VFS pointer is registered and readable.
    let Some(callback) = (unsafe { (*delegated).xDlOpen }) else {
        return ptr::null_mut();
    };
    // SAFETY: SQLite owns the forwarded filename.
    unsafe { callback(delegated, name) }
}

/// SQLite dynamic-loader error boundary forwarded unchanged.
unsafe extern "C" fn vfs_dl_error(vfs: *mut ffi::sqlite3_vfs, len: c_int, message: *mut c_char) {
    // SAFETY: exact callback forwarding after a checked delegated lookup.
    let Ok(delegated) = (unsafe { delegated_vfs(vfs) }) else {
        return;
    };
    // SAFETY: delegated VFS pointer is registered and readable.
    if let Some(callback) = unsafe { (*delegated).xDlError } {
        // SAFETY: SQLite owns the forwarded output buffer.
        unsafe { callback(delegated, len, message) };
    }
}

/// SQLite dynamic symbol boundary forwarded unchanged.
unsafe extern "C" fn vfs_dl_sym(
    vfs: *mut ffi::sqlite3_vfs,
    handle: *mut c_void,
    name: *const c_char,
) -> Option<unsafe extern "C" fn(*mut ffi::sqlite3_vfs, *mut c_void, *const c_char)> {
    // SAFETY: exact callback forwarding after a checked delegated lookup.
    let Ok(delegated) = (unsafe { delegated_vfs(vfs) }) else {
        return None;
    };
    // SAFETY: delegated VFS pointer is registered and readable.
    let callback = (unsafe { (*delegated).xDlSym })?;
    // SAFETY: SQLite owns the forwarded handle and symbol name.
    unsafe { callback(delegated, handle, name) }
}

/// SQLite dynamic-loader close boundary forwarded unchanged.
unsafe extern "C" fn vfs_dl_close(vfs: *mut ffi::sqlite3_vfs, handle: *mut c_void) {
    // SAFETY: exact callback forwarding after a checked delegated lookup.
    let Ok(delegated) = (unsafe { delegated_vfs(vfs) }) else {
        return;
    };
    // SAFETY: delegated VFS pointer is registered and readable.
    if let Some(callback) = unsafe { (*delegated).xDlClose } {
        // SAFETY: SQLite owns the forwarded handle.
        unsafe { callback(delegated, handle) };
    }
}

/// SQLite randomness boundary forwarded unchanged.
unsafe extern "C" fn vfs_randomness(
    vfs: *mut ffi::sqlite3_vfs,
    len: c_int,
    out: *mut c_char,
) -> c_int {
    // SAFETY: exact callback forwarding after a checked delegated lookup.
    let Ok(delegated) = (unsafe { delegated_vfs(vfs) }) else {
        return 0;
    };
    // SAFETY: delegated VFS pointer is registered and readable.
    let Some(callback) = (unsafe { (*delegated).xRandomness }) else {
        return 0;
    };
    // SAFETY: SQLite owns the forwarded output buffer.
    unsafe { callback(delegated, len, out) }
}

/// SQLite sleep boundary forwarded unchanged.
unsafe extern "C" fn vfs_sleep(vfs: *mut ffi::sqlite3_vfs, micros: c_int) -> c_int {
    // SAFETY: exact callback forwarding after a checked delegated lookup.
    let Ok(delegated) = (unsafe { delegated_vfs(vfs) }) else {
        return 0;
    };
    // SAFETY: delegated VFS pointer is registered and readable.
    let Some(callback) = (unsafe { (*delegated).xSleep }) else {
        return 0;
    };
    // SAFETY: scalar-only exact forwarding.
    unsafe { callback(delegated, micros) }
}

/// SQLite current-time boundary forwarded unchanged.
unsafe extern "C" fn vfs_current_time(vfs: *mut ffi::sqlite3_vfs, out: *mut f64) -> c_int {
    // SAFETY: exact callback forwarding after a checked delegated lookup.
    let Ok(delegated) = (unsafe { delegated_vfs(vfs) }) else {
        return ffi::SQLITE_IOERR;
    };
    // SAFETY: delegated VFS pointer is registered and readable.
    let Some(callback) = (unsafe { (*delegated).xCurrentTime }) else {
        return ffi::SQLITE_IOERR;
    };
    // SAFETY: SQLite owns the forwarded output pointer.
    unsafe { callback(delegated, out) }
}

/// SQLite last-error boundary forwarded unchanged.
unsafe extern "C" fn vfs_get_last_error(
    vfs: *mut ffi::sqlite3_vfs,
    len: c_int,
    out: *mut c_char,
) -> c_int {
    // SAFETY: exact callback forwarding after a checked delegated lookup.
    let Ok(delegated) = (unsafe { delegated_vfs(vfs) }) else {
        return 0;
    };
    // SAFETY: delegated VFS pointer is registered and readable.
    let Some(callback) = (unsafe { (*delegated).xGetLastError }) else {
        return 0;
    };
    // SAFETY: SQLite owns the forwarded output pointer.
    unsafe { callback(delegated, len, out) }
}

/// SQLite integer-time boundary forwarded unchanged.
unsafe extern "C" fn vfs_current_time_int64(
    vfs: *mut ffi::sqlite3_vfs,
    out: *mut ffi::sqlite3_int64,
) -> c_int {
    // SAFETY: exact callback forwarding after a checked delegated lookup.
    let Ok(delegated) = (unsafe { delegated_vfs(vfs) }) else {
        return ffi::SQLITE_IOERR;
    };
    // SAFETY: delegated VFS pointer is registered and readable.
    let Some(callback) = (unsafe { (*delegated).xCurrentTimeInt64 }) else {
        return ffi::SQLITE_IOERR;
    };
    // SAFETY: SQLite owns the forwarded output pointer.
    unsafe { callback(delegated, out) }
}

/// SQLite system-call override boundary forwarded unchanged.
unsafe extern "C" fn vfs_set_system_call(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    call: ffi::sqlite3_syscall_ptr,
) -> c_int {
    // SAFETY: exact callback forwarding after a checked delegated lookup.
    let Ok(delegated) = (unsafe { delegated_vfs(vfs) }) else {
        return ffi::SQLITE_NOTFOUND;
    };
    // SAFETY: delegated VFS pointer is registered and readable.
    let Some(callback) = (unsafe { (*delegated).xSetSystemCall }) else {
        return ffi::SQLITE_NOTFOUND;
    };
    // SAFETY: exact SQLite ABI forwarding.
    unsafe { callback(delegated, name, call) }
}

/// SQLite system-call lookup boundary forwarded unchanged.
unsafe extern "C" fn vfs_get_system_call(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
) -> ffi::sqlite3_syscall_ptr {
    // SAFETY: exact callback forwarding after a checked delegated lookup.
    let Ok(delegated) = (unsafe { delegated_vfs(vfs) }) else {
        return None;
    };
    // SAFETY: delegated VFS pointer is registered and readable.
    let callback = (unsafe { (*delegated).xGetSystemCall })?;
    // SAFETY: exact SQLite ABI forwarding.
    unsafe { callback(delegated, name) }
}

/// SQLite system-call enumeration boundary forwarded unchanged.
unsafe extern "C" fn vfs_next_system_call(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
) -> *const c_char {
    // SAFETY: exact callback forwarding after a checked delegated lookup.
    let Ok(delegated) = (unsafe { delegated_vfs(vfs) }) else {
        return ptr::null();
    };
    // SAFETY: delegated VFS pointer is registered and readable.
    let Some(callback) = (unsafe { (*delegated).xNextSystemCall }) else {
        return ptr::null();
    };
    // SAFETY: exact SQLite ABI forwarding.
    unsafe { callback(delegated, name) }
}

/// Delegated file close boundary.
unsafe extern "C" fn io_close(file: *mut ffi::sqlite3_file) -> c_int {
    // SAFETY: wrapper contains a live delegated file until this callback returns.
    let Ok(real) = (unsafe { real_file(file) }) else {
        return ffi::SQLITE_IOERR_CLOSE;
    };
    // SAFETY: delegated file was initialized by successful xOpen.
    let Ok(methods) = (unsafe { io_methods(real) }) else {
        return ffi::SQLITE_IOERR_CLOSE;
    };
    // SAFETY: method table is live for this delegated file.
    let Some(callback) = (unsafe { (*methods).xClose }) else {
        return ffi::SQLITE_IOERR_CLOSE;
    };
    // SAFETY: close receives its exact delegated file pointer.
    let result = unsafe { callback(real) };
    // SAFETY: prevent reuse of the wrapper after delegated close.
    unsafe { (*file).pMethods = ptr::null() };
    result
}

/// Delegated file read boundary with deterministic fault observation.
unsafe extern "C" fn io_read(
    file: *mut ffi::sqlite3_file,
    out: *mut c_void,
    amount: c_int,
    offset: ffi::sqlite3_int64,
) -> c_int {
    // SAFETY: callback arguments are supplied by SQLite for this live file.
    let Ok(real) = (unsafe { before_io(file, Operation::Read) }) else {
        return ffi::SQLITE_IOERR_READ;
    };
    // SAFETY: delegated file was initialized by successful xOpen.
    let Ok(methods) = (unsafe { io_methods(real) }) else {
        return ffi::SQLITE_IOERR_READ;
    };
    // SAFETY: method table is live for this delegated file.
    let Some(callback) = (unsafe { (*methods).xRead }) else {
        return ffi::SQLITE_IOERR_READ;
    };
    // SAFETY: exact SQLite buffer and scalar forwarding.
    unsafe { callback(real, out, amount, offset) }
}

/// Delegated file write boundary with deterministic FULL/IOERR observation.
unsafe extern "C" fn io_write(
    file: *mut ffi::sqlite3_file,
    input: *const c_void,
    amount: c_int,
    offset: ffi::sqlite3_int64,
) -> c_int {
    // SAFETY: callback arguments are supplied by SQLite for this live file.
    let real = match unsafe { before_io(file, Operation::Write) } {
        Ok(real) => real,
        Err(code) => return code,
    };
    // SAFETY: delegated file was initialized by successful xOpen.
    let Ok(methods) = (unsafe { io_methods(real) }) else {
        return ffi::SQLITE_IOERR_WRITE;
    };
    // SAFETY: method table is live for this delegated file.
    let Some(callback) = (unsafe { (*methods).xWrite }) else {
        return ffi::SQLITE_IOERR_WRITE;
    };
    // SAFETY: exact SQLite buffer and scalar forwarding.
    unsafe { callback(real, input, amount, offset) }
}

/// Delegated truncate boundary with deterministic IOERR observation.
unsafe extern "C" fn io_truncate(file: *mut ffi::sqlite3_file, size: ffi::sqlite3_int64) -> c_int {
    // SAFETY: callback file is supplied by SQLite for this live wrapper.
    let real = match unsafe { before_io(file, Operation::Truncate) } {
        Ok(real) => real,
        Err(code) => return code,
    };
    // SAFETY: delegated file and table were initialized by xOpen.
    let Ok(methods) = (unsafe { io_methods(real) }) else {
        return ffi::SQLITE_IOERR_TRUNCATE;
    };
    // SAFETY: method table is live for this delegated file.
    let Some(callback) = (unsafe { (*methods).xTruncate }) else {
        return ffi::SQLITE_IOERR_TRUNCATE;
    };
    // SAFETY: scalar-only exact forwarding.
    unsafe { callback(real, size) }
}

/// Delegated sync boundary with deterministic IOERR/pause observation.
unsafe extern "C" fn io_sync(file: *mut ffi::sqlite3_file, flags: c_int) -> c_int {
    // SAFETY: callback file is supplied by SQLite for this live wrapper.
    let real = match unsafe { before_io(file, Operation::Sync) } {
        Ok(real) => real,
        Err(code) => return code,
    };
    // SAFETY: delegated file and table were initialized by xOpen.
    let Ok(methods) = (unsafe { io_methods(real) }) else {
        return ffi::SQLITE_IOERR_FSYNC;
    };
    // SAFETY: method table is live for this delegated file.
    let Some(callback) = (unsafe { (*methods).xSync }) else {
        return ffi::SQLITE_IOERR_FSYNC;
    };
    // SAFETY: scalar-only exact forwarding.
    unsafe { callback(real, flags) }
}

/// Delegated file-size boundary.
unsafe extern "C" fn io_file_size(
    file: *mut ffi::sqlite3_file,
    out: *mut ffi::sqlite3_int64,
) -> c_int {
    // SAFETY: callback file is supplied by SQLite for this live wrapper.
    let Ok(real) = (unsafe { real_file(file) }) else {
        return ffi::SQLITE_IOERR_FSTAT;
    };
    // SAFETY: delegated file and table were initialized by xOpen.
    let Ok(methods) = (unsafe { io_methods(real) }) else {
        return ffi::SQLITE_IOERR_FSTAT;
    };
    // SAFETY: method table is live for this delegated file.
    let Some(callback) = (unsafe { (*methods).xFileSize }) else {
        return ffi::SQLITE_IOERR_FSTAT;
    };
    // SAFETY: SQLite owns the exact forwarded output pointer.
    unsafe { callback(real, out) }
}

/// Delegated lock boundary with deterministic lock-family IOERR observation.
unsafe extern "C" fn io_lock(file: *mut ffi::sqlite3_file, level: c_int) -> c_int {
    // SAFETY: callback file is supplied by SQLite for this live wrapper.
    let real = match unsafe { before_io(file, Operation::Lock) } {
        Ok(real) => real,
        Err(code) => return code,
    };
    // SAFETY: delegated file and table were initialized by xOpen.
    let Ok(methods) = (unsafe { io_methods(real) }) else {
        return ffi::SQLITE_IOERR_LOCK;
    };
    // SAFETY: method table is live for this delegated file.
    let Some(callback) = (unsafe { (*methods).xLock }) else {
        return ffi::SQLITE_IOERR_LOCK;
    };
    // SAFETY: scalar-only exact forwarding.
    unsafe { callback(real, level) }
}

/// Delegated unlock boundary with deterministic lock-family IOERR observation.
unsafe extern "C" fn io_unlock(file: *mut ffi::sqlite3_file, level: c_int) -> c_int {
    // SAFETY: callback file is supplied by SQLite for this live wrapper.
    let real = match unsafe { before_io(file, Operation::Unlock) } {
        Ok(real) => real,
        Err(code) => return code,
    };
    // SAFETY: delegated file and table were initialized by xOpen.
    let Ok(methods) = (unsafe { io_methods(real) }) else {
        return ffi::SQLITE_IOERR_UNLOCK;
    };
    // SAFETY: method table is live for this delegated file.
    let Some(callback) = (unsafe { (*methods).xUnlock }) else {
        return ffi::SQLITE_IOERR_UNLOCK;
    };
    // SAFETY: scalar-only exact forwarding.
    unsafe { callback(real, level) }
}

/// Delegated reserved-lock query with deterministic lock-family IOERR observation.
unsafe extern "C" fn io_check_reserved_lock(
    file: *mut ffi::sqlite3_file,
    out: *mut c_int,
) -> c_int {
    // SAFETY: callback file is supplied by SQLite for this live wrapper.
    let real = match unsafe { before_io(file, Operation::CheckReservedLock) } {
        Ok(real) => real,
        Err(code) => return code,
    };
    // SAFETY: delegated file and table were initialized by xOpen.
    let Ok(methods) = (unsafe { io_methods(real) }) else {
        return ffi::SQLITE_IOERR_CHECKRESERVEDLOCK;
    };
    // SAFETY: method table is live for this delegated file.
    let Some(callback) = (unsafe { (*methods).xCheckReservedLock }) else {
        return ffi::SQLITE_IOERR_CHECKRESERVEDLOCK;
    };
    // SAFETY: SQLite owns the exact forwarded output pointer.
    unsafe { callback(real, out) }
}

/// Delegated file-control boundary.
unsafe extern "C" fn io_file_control(
    file: *mut ffi::sqlite3_file,
    operation: c_int,
    argument: *mut c_void,
) -> c_int {
    // SAFETY: callback file is supplied by SQLite for this live wrapper.
    let Ok(real) = (unsafe { real_file(file) }) else {
        return ffi::SQLITE_NOTFOUND;
    };
    // SAFETY: delegated file and table were initialized by xOpen.
    let Ok(methods) = (unsafe { io_methods(real) }) else {
        return ffi::SQLITE_NOTFOUND;
    };
    // SAFETY: method table is live for this delegated file.
    let Some(callback) = (unsafe { (*methods).xFileControl }) else {
        return ffi::SQLITE_NOTFOUND;
    };
    // SAFETY: exact SQLite ABI forwarding.
    unsafe { callback(real, operation, argument) }
}

/// Delegated sector-size boundary.
unsafe extern "C" fn io_sector_size(file: *mut ffi::sqlite3_file) -> c_int {
    // SAFETY: callback file is supplied by SQLite for this live wrapper.
    let Ok(real) = (unsafe { real_file(file) }) else {
        return 0;
    };
    // SAFETY: delegated file and table were initialized by xOpen.
    let Ok(methods) = (unsafe { io_methods(real) }) else {
        return 0;
    };
    // SAFETY: method table is live for this delegated file.
    let Some(callback) = (unsafe { (*methods).xSectorSize }) else {
        return 0;
    };
    // SAFETY: exact delegated file forwarding.
    unsafe { callback(real) }
}

/// Delegated device-characteristics boundary.
unsafe extern "C" fn io_device_characteristics(file: *mut ffi::sqlite3_file) -> c_int {
    // SAFETY: callback file is supplied by SQLite for this live wrapper.
    let Ok(real) = (unsafe { real_file(file) }) else {
        return 0;
    };
    // SAFETY: delegated file and table were initialized by xOpen.
    let Ok(methods) = (unsafe { io_methods(real) }) else {
        return 0;
    };
    // SAFETY: method table is live for this delegated file.
    let Some(callback) = (unsafe { (*methods).xDeviceCharacteristics }) else {
        return 0;
    };
    // SAFETY: exact delegated file forwarding.
    unsafe { callback(real) }
}

/// Delegated shared-memory map boundary; any call is retained as baseline-invalid.
unsafe extern "C" fn io_shm_map(
    file: *mut ffi::sqlite3_file,
    page: c_int,
    page_size: c_int,
    extend: c_int,
    out: *mut *mut c_void,
) -> c_int {
    // SAFETY: callback file is supplied by SQLite for this live wrapper.
    let Ok(real) = (unsafe { before_shared_memory(file) }) else {
        return ffi::SQLITE_IOERR_SHMMAP;
    };
    // SAFETY: delegated file and table were initialized by xOpen.
    let Ok(methods) = (unsafe { io_methods(real) }) else {
        return ffi::SQLITE_IOERR_SHMMAP;
    };
    // SAFETY: method table is live for this delegated file.
    let Some(callback) = (unsafe { (*methods).xShmMap }) else {
        return ffi::SQLITE_IOERR_SHMMAP;
    };
    // SAFETY: exact SQLite ABI forwarding.
    unsafe { callback(real, page, page_size, extend, out) }
}

/// Delegated shared-memory lock boundary; any call is retained as baseline-invalid.
unsafe extern "C" fn io_shm_lock(
    file: *mut ffi::sqlite3_file,
    offset: c_int,
    count: c_int,
    flags: c_int,
) -> c_int {
    // SAFETY: callback file is supplied by SQLite for this live wrapper.
    let Ok(real) = (unsafe { before_shared_memory(file) }) else {
        return ffi::SQLITE_IOERR_SHMLOCK;
    };
    // SAFETY: delegated file and table were initialized by xOpen.
    let Ok(methods) = (unsafe { io_methods(real) }) else {
        return ffi::SQLITE_IOERR_SHMLOCK;
    };
    // SAFETY: method table is live for this delegated file.
    let Some(callback) = (unsafe { (*methods).xShmLock }) else {
        return ffi::SQLITE_IOERR_SHMLOCK;
    };
    // SAFETY: exact SQLite ABI forwarding.
    unsafe { callback(real, offset, count, flags) }
}

/// Delegated shared-memory barrier; any call is retained as baseline-invalid.
unsafe extern "C" fn io_shm_barrier(file: *mut ffi::sqlite3_file) {
    // SAFETY: callback file is supplied by SQLite for this live wrapper.
    let Ok(real) = (unsafe { before_shared_memory(file) }) else {
        return;
    };
    // SAFETY: delegated file and table were initialized by xOpen.
    let Ok(methods) = (unsafe { io_methods(real) }) else {
        return;
    };
    // SAFETY: method table is live for this delegated file.
    if let Some(callback) = unsafe { (*methods).xShmBarrier } {
        // SAFETY: exact delegated file forwarding.
        unsafe { callback(real) };
    }
}

/// Delegated shared-memory unmap; any call is retained as baseline-invalid.
unsafe extern "C" fn io_shm_unmap(file: *mut ffi::sqlite3_file, delete: c_int) -> c_int {
    // SAFETY: callback file is supplied by SQLite for this live wrapper.
    let Ok(real) = (unsafe { before_shared_memory(file) }) else {
        return ffi::SQLITE_IOERR_SHMOPEN;
    };
    // SAFETY: delegated file and table were initialized by xOpen.
    let Ok(methods) = (unsafe { io_methods(real) }) else {
        return ffi::SQLITE_IOERR_SHMOPEN;
    };
    // SAFETY: method table is live for this delegated file.
    let Some(callback) = (unsafe { (*methods).xShmUnmap }) else {
        return ffi::SQLITE_IOERR_SHMOPEN;
    };
    // SAFETY: exact SQLite ABI forwarding.
    unsafe { callback(real, delete) }
}

/// Delegated memory-map fetch boundary with bounded observation.
unsafe extern "C" fn io_fetch(
    file: *mut ffi::sqlite3_file,
    offset: ffi::sqlite3_int64,
    amount: c_int,
    out: *mut *mut c_void,
) -> c_int {
    // SAFETY: callback file is supplied by SQLite for this live wrapper.
    let Ok(real) = (unsafe { before_io(file, Operation::Fetch) }) else {
        return ffi::SQLITE_IOERR;
    };
    // SAFETY: delegated file and table were initialized by xOpen.
    let Ok(methods) = (unsafe { io_methods(real) }) else {
        return ffi::SQLITE_IOERR;
    };
    // SAFETY: method table is live for this delegated file.
    let Some(callback) = (unsafe { (*methods).xFetch }) else {
        if !out.is_null() {
            // SAFETY: SQLite supplied this output slot for xFetch.
            unsafe { *out = ptr::null_mut() };
        }
        return ffi::SQLITE_OK;
    };
    // SAFETY: exact SQLite ABI forwarding.
    unsafe { callback(real, offset, amount, out) }
}

/// Delegated memory-map unfetch boundary with bounded observation.
unsafe extern "C" fn io_unfetch(
    file: *mut ffi::sqlite3_file,
    offset: ffi::sqlite3_int64,
    mapped: *mut c_void,
) -> c_int {
    // SAFETY: callback file is supplied by SQLite for this live wrapper.
    let Ok(real) = (unsafe { before_io(file, Operation::Fetch) }) else {
        return ffi::SQLITE_IOERR;
    };
    // SAFETY: delegated file and table were initialized by xOpen.
    let Ok(methods) = (unsafe { io_methods(real) }) else {
        return ffi::SQLITE_IOERR;
    };
    // SAFETY: method table is live for this delegated file.
    let Some(callback) = (unsafe { (*methods).xUnfetch }) else {
        return ffi::SQLITE_OK;
    };
    // SAFETY: exact SQLite ABI forwarding.
    unsafe { callback(real, offset, mapped) }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use super::*;

    #[test]
    fn open_flags_classify_every_closed_file_role() {
        assert_eq!(
            classify_open(ffi::SQLITE_OPEN_MAIN_DB),
            (FileRole::MainDatabase, RoleEvidence::MainFlag)
        );
        assert_eq!(
            classify_open(ffi::SQLITE_OPEN_MAIN_JOURNAL),
            (FileRole::RollbackJournal, RoleEvidence::JournalFlag)
        );
        assert_eq!(
            classify_open(ffi::SQLITE_OPEN_WAL),
            (FileRole::Wal, RoleEvidence::WalFlag)
        );
        assert_eq!(
            classify_open(ffi::SQLITE_OPEN_TEMP_DB),
            (FileRole::Temporary, RoleEvidence::TemporaryFlag)
        );
        assert_eq!(
            classify_open(ffi::SQLITE_OPEN_MAIN_DB | ffi::SQLITE_OPEN_WAL),
            (FileRole::Unknown, RoleEvidence::Unknown)
        );
    }

    #[test]
    fn delete_suffixes_classify_without_retaining_paths() {
        for (name, expected) in [
            (
                "case.db-journal",
                (FileRole::RollbackJournal, RoleEvidence::JournalName),
            ),
            ("case.db-wal", (FileRole::Wal, RoleEvidence::WalName)),
            (
                "case.db-shm",
                (FileRole::SharedMemory, RoleEvidence::SharedMemoryName),
            ),
            (
                "temporary",
                (FileRole::Temporary, RoleEvidence::TemporaryName),
            ),
        ] {
            let name = CString::new(name).expect("static filename");
            // SAFETY: the CString remains alive and NUL-terminated for the call.
            assert_eq!(unsafe { classify_delete(name.as_ptr()) }, expected);
        }
    }
}
