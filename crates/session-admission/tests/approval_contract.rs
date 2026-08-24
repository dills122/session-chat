use session_admission::{
    AdmissionContractError, AdmissionMethod, ApprovalContext, ApprovalDecision, PendingAdmission,
};

const INVITATION_ID: [u8; 16] = [0x11; 16];
const REQUEST_ID: [u8; 16] = [0x22; 16];
const KEY_PACKAGE_REFERENCE: [u8; 32] = [0x33; 32];
const EXPIRES_AT: u64 = 1_700_000_120;

struct FakePendingAdmission(ApprovalContext);

impl PendingAdmission for FakePendingAdmission {
    fn approval_context(&self) -> ApprovalContext {
        self.0
    }
}

fn context() -> ApprovalContext {
    ApprovalContext::new(
        AdmissionMethod::SecretCapability,
        INVITATION_ID,
        REQUEST_ID,
        KEY_PACKAGE_REFERENCE,
        EXPIRES_AT,
    )
    .expect("nonzero fixed test context")
}

#[test]
fn approval_contract_is_object_safe_and_carries_no_membership_authority() {
    let pending: Box<dyn PendingAdmission> = Box::new(FakePendingAdmission(context()));
    let observed = pending.approval_context();

    assert_eq!(observed.method(), AdmissionMethod::SecretCapability);
    assert_eq!(observed.invitation_id(), &INVITATION_ID);
    assert_eq!(observed.join_request_id(), &REQUEST_ID);
    assert_eq!(observed.key_package_reference(), &KEY_PACKAGE_REFERENCE);
    assert_eq!(observed.expires_at_unix_seconds(), EXPIRES_AT);
    assert_eq!(ApprovalDecision::Approve, ApprovalDecision::Approve);
    assert_ne!(ApprovalDecision::Approve, ApprovalDecision::Reject);
}

#[test]
fn invalid_or_ambiguous_approval_context_is_rejected() {
    for (invitation_id, request_id, key_package_reference, expires_at) in [
        ([0; 16], REQUEST_ID, KEY_PACKAGE_REFERENCE, EXPIRES_AT),
        (INVITATION_ID, [0; 16], KEY_PACKAGE_REFERENCE, EXPIRES_AT),
        (INVITATION_ID, REQUEST_ID, [0; 32], EXPIRES_AT),
        (INVITATION_ID, REQUEST_ID, KEY_PACKAGE_REFERENCE, 0),
    ] {
        assert_eq!(
            ApprovalContext::new(
                AdmissionMethod::SecretCapability,
                invitation_id,
                request_id,
                key_package_reference,
                expires_at,
            ),
            Err(AdmissionContractError::InvalidContext)
        );
    }
}

#[test]
fn approval_context_debug_output_redacts_identifiers_and_key_reference() {
    let rendered = format!("{:?}", context());

    assert!(rendered.contains("SecretCapability"));
    assert!(rendered.contains("expires_at_unix_seconds"));
    assert!(!rendered.contains("invitation_id"));
    assert!(!rendered.contains("join_request_id"));
    assert!(!rendered.contains("key_package_reference"));
    assert!(!rendered.contains("17, 17"));
    assert!(!rendered.contains("34, 34"));
    assert!(!rendered.contains("51, 51"));
}
