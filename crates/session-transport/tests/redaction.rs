use session_protocol::{DepositCapability, LocalWelcomeDepositEndpoint, OpaqueEnvelope};
use session_transport::{LocalMailboxPolicy, LocalMemoryWelcomeTransport, LocalTransportError};

const NOW: u64 = 1_700_000_000;

#[test]
fn rejected_deposit_diagnostics_exclude_seeded_authority_and_envelope_bytes() {
    let policy = LocalMailboxPolicy::new(60, 1).expect("bounded policy");
    let mut transport = LocalMemoryWelcomeTransport::new(policy).expect("local transport");
    let seeded_authority = [b'S'; 32];
    let seeded_ciphertext = vec![b'C'; 48];
    let foreign_endpoint = LocalWelcomeDepositEndpoint::new(
        [0x41; 16],
        [0x42; 16],
        DepositCapability::new(seeded_authority).expect("nonzero deposit authority"),
        NOW + 60,
    )
    .expect("structurally valid foreign endpoint");
    let envelope = OpaqueEnvelope::new([0x43; 16], NOW + 30, seeded_ciphertext.clone())
        .expect("bounded opaque envelope");

    let failure = transport
        .deposit(&foreign_endpoint, envelope, NOW)
        .expect_err("foreign endpoint must fail closed");
    let diagnostics = format!("{failure:?} {failure}");

    assert_eq!(failure, LocalTransportError::Rejected);
    assert_eq!(diagnostics, "Rejected local mailbox operation rejected");
    assert!(
        !diagnostics
            .as_bytes()
            .windows(seeded_authority.len())
            .any(|window| window == seeded_authority)
    );
    assert!(
        !diagnostics
            .as_bytes()
            .windows(seeded_ciphertext.len())
            .any(|window| window == seeded_ciphertext)
    );
}
