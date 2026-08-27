#![forbid(unsafe_code)]

#[cfg(not(session_chat_storage_fault_testing))]
fn main() {
    unavailable();
}

#[cfg(session_chat_storage_fault_testing)]
fn main() {
    unavailable();
}

fn unavailable() -> ! {
    eprintln!("sessionctl-l2: unavailable");
    std::process::exit(2);
}
