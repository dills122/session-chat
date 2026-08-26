#![forbid(unsafe_code)]

fn main() {
    let mut arguments = std::env::args().skip(1);
    let mode = arguments.next();
    if arguments.next().is_some()
        || mode
            .as_deref()
            .is_some_and(|value| value != "--evidence-v1")
    {
        eprintln!("sessionctl: unsupported invocation");
        std::process::exit(2);
    }
    match sessionctl::run_phase_one_demo() {
        Ok(report) => {
            if mode.is_some() {
                print!("{}", report.encode_scenario_evidence_v1());
            } else {
                println!("admission: approved");
                println!("welcome: delivered");
                println!("messages: {}", report.application_messages_received());
                println!("epoch: {}", report.updated_epoch());
                println!("removal: enforced");
            }
        }
        Err(_) => {
            eprintln!("sessionctl: headless conformance flow failed");
            std::process::exit(1);
        }
    }
}
