#![forbid(unsafe_code)]

#[cfg(not(session_chat_storage_fault_testing))]
fn main() {
    unavailable();
}

#[cfg(session_chat_storage_fault_testing)]
fn main() {
    use std::{ffi::OsString, path::PathBuf};

    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let result = match arguments.as_slice() {
        [mode, role, root] if mode == "--internal-role" => {
            let Some(role) = role.to_str() else {
                unsupported();
            };
            sessionctl::l2_process::run_l2_process_internal_role(role, PathBuf::from(root))
        }
        _ => unsupported(),
    };
    if result.is_err() {
        eprintln!("sessionctl-l2: internal role failed");
        std::process::exit(1);
    }
}

#[cfg(not(session_chat_storage_fault_testing))]
fn unavailable() -> ! {
    eprintln!("sessionctl-l2: unavailable");
    std::process::exit(2);
}

#[cfg(session_chat_storage_fault_testing)]
fn unsupported() -> ! {
    eprintln!("sessionctl-l2: unsupported invocation");
    std::process::exit(2);
}
