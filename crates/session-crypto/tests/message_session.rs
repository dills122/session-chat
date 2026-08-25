use session_crypto::{
    ApplicationMessage, MAX_APPLICATION_MESSAGE_BYTES, MAX_PROTECTED_MESSAGE_BYTES, MessageEvent,
    MessageSession, MessageSessionError, ProtectedMessage,
};

struct EchoSession;

impl MessageSession for EchoSession {
    fn epoch(&self) -> u64 {
        7
    }

    fn member_count(&self) -> usize {
        2
    }

    fn protect_application_message(
        &mut self,
        plaintext: &[u8],
    ) -> Result<ProtectedMessage, MessageSessionError> {
        ProtectedMessage::from_bytes(plaintext)
    }

    fn process_protected_message(
        &mut self,
        message: ProtectedMessage,
    ) -> Result<MessageEvent, MessageSessionError> {
        Ok(MessageEvent::Application(ApplicationMessage::from_vec(
            message.into_bytes(),
        )?))
    }
}

#[test]
fn contract_is_object_safe_and_provider_neutral() -> Result<(), MessageSessionError> {
    let mut session: Box<dyn MessageSession> = Box::new(EchoSession);

    assert_eq!(session.epoch(), 7);
    assert_eq!(session.member_count(), 2);
    let protected = session.protect_application_message(b"hello")?;
    assert_eq!(
        session.process_protected_message(protected)?,
        MessageEvent::Application(ApplicationMessage::from_bytes(b"hello")?)
    );

    Ok(())
}

#[test]
fn protected_messages_are_bounded_before_storage() {
    assert!(ProtectedMessage::from_bytes(&vec![0; MAX_PROTECTED_MESSAGE_BYTES]).is_ok());
    assert_eq!(
        ProtectedMessage::from_bytes(&vec![0; MAX_PROTECTED_MESSAGE_BYTES + 1]),
        Err(MessageSessionError::InputTooLarge)
    );
}

#[test]
fn application_plaintext_and_protected_bytes_are_redacted_from_debug() {
    let secret = b"do not log this";
    let event = MessageEvent::Application(
        ApplicationMessage::from_bytes(secret).expect("bounded test plaintext"),
    );
    let protected = ProtectedMessage::from_bytes(secret).expect("bounded test message");

    assert!(!format!("{event:?}").contains("do not log this"));
    assert!(!format!("{protected:?}").contains("do not log this"));
    assert_eq!(MAX_APPLICATION_MESSAGE_BYTES, 16 * 1024);
}

#[test]
fn application_messages_are_bounded_and_redacted() {
    assert!(ApplicationMessage::from_bytes(&vec![0; MAX_APPLICATION_MESSAGE_BYTES]).is_ok());
    assert_eq!(
        ApplicationMessage::from_bytes(&vec![0; MAX_APPLICATION_MESSAGE_BYTES + 1]),
        Err(MessageSessionError::InputTooLarge)
    );
}

#[test]
fn owned_message_constructors_preserve_exact_bytes_and_enforce_both_bounds() {
    let protected =
        ProtectedMessage::from_vec(b"protected".to_vec()).expect("bounded protected message");
    assert_eq!(protected.as_bytes(), b"protected");
    assert_eq!(protected.into_bytes(), b"protected");
    assert_eq!(
        ProtectedMessage::from_vec(vec![0; MAX_PROTECTED_MESSAGE_BYTES + 1]),
        Err(MessageSessionError::InputTooLarge)
    );

    let application =
        ApplicationMessage::from_vec(b"plaintext".to_vec()).expect("bounded plaintext");
    assert_eq!(application.as_bytes(), b"plaintext");
    assert_eq!(application.into_bytes(), b"plaintext");
    assert_eq!(
        ApplicationMessage::from_vec(vec![0; MAX_APPLICATION_MESSAGE_BYTES + 1]),
        Err(MessageSessionError::InputTooLarge)
    );
}

#[test]
fn coarse_errors_and_membership_events_have_stable_non_secret_diagnostics() {
    assert_eq!(
        MessageSessionError::InputTooLarge.to_string(),
        "message exceeds the configured bound"
    );
    assert_eq!(
        MessageSessionError::Rejected.to_string(),
        "message operation rejected"
    );
    assert_eq!(
        format!("{:?}", MessageEvent::EpochAdvanced),
        "EpochAdvanced"
    );
    assert_eq!(format!("{:?}", MessageEvent::Removed), "Removed");
}
