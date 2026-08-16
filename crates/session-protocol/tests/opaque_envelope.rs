use session_protocol::{
    MAX_ENVELOPE_CIPHERTEXT_BYTES, MAX_WIRE_OBJECT_BYTES, OpaqueEnvelope, WireError, WireObjectType,
};

const ENVELOPE_ID: [u8; 16] = [0x11; 16];

fn envelope() -> OpaqueEnvelope {
    OpaqueEnvelope::new(ENVELOPE_ID, 42, b"abc".to_vec())
        .expect("the fixture is within protocol limits")
}

fn canonical_fixture() -> Vec<u8> {
    vec![
        0x85, 0x01, 0x01, 0x50, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x18, 0x2a, 0x43, b'a', b'b', b'c',
    ]
}

#[test]
fn emits_the_committed_deterministic_fixture() {
    assert_eq!(
        envelope().encode_canonical().expect("encoding succeeds"),
        canonical_fixture()
    );
}

#[test]
fn round_trips_ciphertext_without_identity_or_message_metadata() {
    let decoded = OpaqueEnvelope::decode_canonical(&canonical_fixture()).expect("fixture decodes");

    assert_eq!(decoded.object_type(), WireObjectType::OpaqueEnvelope);
    assert_eq!(decoded.envelope_id(), &ENVELOPE_ID);
    assert_eq!(decoded.expires_at_unix_seconds(), 42);
    assert_eq!(decoded.ciphertext(), b"abc");
}

#[test]
fn rejects_a_non_deterministic_integer_representation() {
    let mut bytes = canonical_fixture();
    bytes.splice(1..2, [0x18, 0x01]);

    assert_eq!(
        OpaqueEnvelope::decode_canonical(&bytes),
        Err(WireError::NonDeterministicEncoding)
    );
}

#[test]
fn rejects_unknown_versions_and_object_types() {
    let mut unknown_version = canonical_fixture();
    unknown_version[1] = 0x02;
    assert_eq!(
        OpaqueEnvelope::decode_canonical(&unknown_version),
        Err(WireError::UnsupportedVersion(2))
    );

    let mut unknown_type = canonical_fixture();
    unknown_type[2] = 0x07;
    assert_eq!(
        OpaqueEnvelope::decode_canonical(&unknown_type),
        Err(WireError::UnsupportedObjectType(7))
    );

    let mut invitation_type = canonical_fixture();
    invitation_type[2] = WireObjectType::SignedCapabilityInvitation as u8;
    assert_eq!(
        OpaqueEnvelope::decode_canonical(&invitation_type),
        Err(WireError::UnsupportedObjectType(
            WireObjectType::SignedCapabilityInvitation as u16
        ))
    );
}

#[test]
fn rejects_wrong_cbor_types_for_every_envelope_field() {
    let canonical = canonical_fixture();
    let field_offsets = [1, 2, 3, 20, 22];

    for offset in field_offsets {
        let mut wrong_type = canonical.clone();
        wrong_type[offset] = if matches!(offset, 1 | 2 | 20) {
            0x40 // empty byte string where an integer is required
        } else {
            0x00 // integer where a byte string is required
        };
        assert_eq!(
            OpaqueEnvelope::decode_canonical(&wrong_type),
            Err(WireError::Malformed),
            "wrong CBOR type at byte {offset} must fail"
        );
    }
}

#[test]
fn rejects_wrong_field_counts_identifier_lengths_and_trailing_bytes() {
    let mut wrong_field_count = canonical_fixture();
    wrong_field_count[0] = 0x84;
    assert_eq!(
        OpaqueEnvelope::decode_canonical(&wrong_field_count),
        Err(WireError::Malformed)
    );

    let mut short_identifier = canonical_fixture();
    short_identifier[3] = 0x4f;
    assert_eq!(
        OpaqueEnvelope::decode_canonical(&short_identifier),
        Err(WireError::InvalidEnvelopeIdLength(15))
    );

    let mut trailing = canonical_fixture();
    trailing.push(0);
    assert_eq!(
        OpaqueEnvelope::decode_canonical(&trailing),
        Err(WireError::TrailingData)
    );
}

#[test]
fn rejects_oversized_ciphertext_and_wire_objects_before_processing() {
    assert_eq!(
        OpaqueEnvelope::new(ENVELOPE_ID, 42, vec![0; MAX_ENVELOPE_CIPHERTEXT_BYTES + 1],),
        Err(WireError::CiphertextTooLarge {
            actual: MAX_ENVELOPE_CIPHERTEXT_BYTES + 1,
            maximum: MAX_ENVELOPE_CIPHERTEXT_BYTES,
        })
    );

    let oversized = vec![0; MAX_WIRE_OBJECT_BYTES + 1];
    assert_eq!(
        OpaqueEnvelope::decode_canonical(&oversized),
        Err(WireError::WireObjectTooLarge {
            actual: MAX_WIRE_OBJECT_BYTES + 1,
            maximum: MAX_WIRE_OBJECT_BYTES,
        })
    );

    let mut oversized_ciphertext = canonical_fixture();
    oversized_ciphertext.truncate(22);
    oversized_ciphertext.extend([0x59, 0xf0, 0x01]);
    oversized_ciphertext.extend(vec![0; MAX_ENVELOPE_CIPHERTEXT_BYTES + 1]);
    assert_eq!(
        OpaqueEnvelope::decode_canonical(&oversized_ciphertext),
        Err(WireError::CiphertextTooLarge {
            actual: MAX_ENVELOPE_CIPHERTEXT_BYTES + 1,
            maximum: MAX_ENVELOPE_CIPHERTEXT_BYTES,
        })
    );
}

#[test]
fn rejects_indefinite_length_arrays_and_byte_strings() {
    let mut indefinite_array = canonical_fixture();
    indefinite_array[0] = 0x9f;
    indefinite_array.push(0xff);
    assert_eq!(
        OpaqueEnvelope::decode_canonical(&indefinite_array),
        Err(WireError::Malformed)
    );

    let mut indefinite_ciphertext = canonical_fixture();
    indefinite_ciphertext[22] = 0x5f;
    assert_eq!(
        OpaqueEnvelope::decode_canonical(&indefinite_ciphertext),
        Err(WireError::Malformed)
    );
}

#[test]
fn accepts_the_exact_ciphertext_size_boundary() {
    let envelope = OpaqueEnvelope::new(ENVELOPE_ID, 42, vec![0; MAX_ENVELOPE_CIPHERTEXT_BYTES])
        .expect("the exact limit is accepted");
    let encoded = envelope.encode_canonical().expect("boundary encodes");
    let decoded = OpaqueEnvelope::decode_canonical(&encoded).expect("boundary decodes");

    assert_eq!(decoded.ciphertext().len(), MAX_ENVELOPE_CIPHERTEXT_BYTES);
}
