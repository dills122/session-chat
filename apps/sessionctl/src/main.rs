#![forbid(unsafe_code)]

fn main() {
    match sessionctl::run_phase_one_demo() {
        Ok(report) => {
            println!("admission: approved");
            println!("welcome: delivered");
            println!("messages: {}", report.application_messages_received());
            println!("epoch: {}", report.updated_epoch());
            println!("removal: enforced");
        }
        Err(_) => {
            eprintln!("sessionctl: headless conformance flow failed");
            std::process::exit(1);
        }
    }
}
