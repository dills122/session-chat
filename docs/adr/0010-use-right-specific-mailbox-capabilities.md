# ADR 0010: Use right-specific mailbox capabilities

Status: accepted for transport and rendezvous interfaces

Date: 2026-08-16

## Context

The original illustrative `EnvelopeTransport` accepted one `MailboxId` for both
send and receive and acknowledged by `DeliveryId` alone. Real rendezvous and
first-contact mailboxes require distinct authority to deposit, read,
acknowledge/delete, and rotate. A shared identifier forces adapters either to
hide ambient credentials or to overload an identifier with secrets that can
leak into logs and send paths.

## Decision

Transport and mailbox APIs use capability types scoped to one right:

```rust
struct DepositEndpoint { /* route + mailbox id + deposit authority */ }
struct ReceiveCapability { /* route + mailbox id + read authority */ }
struct AcknowledgementCapability { /* mailbox + delivery-scoped delete authority */ }
struct RotationCapability { /* mailbox continuity/rotation authority */ }

trait EnvelopeTransport {
    async fn send(
        &self,
        destination: &DepositEndpoint,
        envelope: OpaqueEnvelope,
    ) -> Result<DeliveryId>;

    async fn receive(
        &self,
        authority: &ReceiveCapability,
        cursor: Option<Cursor>,
    ) -> Result<Vec<ReceivedEnvelope>>;

    async fn acknowledge(
        &self,
        authority: &AcknowledgementCapability,
        delivery: DeliveryId,
    ) -> Result<()>;
}
```

The final types may separate public routing data from secret bytes further, but
they must preserve these authority boundaries. Secret-bearing types do not
implement `Debug` or `Display`, are not included in generic error context or
telemetry, and are zeroized when ownership permits. Deposit endpoints can be
shared with senders; receive, acknowledgement, and rotation authority cannot.

Adapters must not obtain mailbox rights from ambient global credentials. A
transport profile selects routing and privacy behavior; it does not grant
mailbox authority. Invitation publication remains outside this interface.

## Alternatives considered

### One mailbox URL or identifier for every operation

Rejected. It creates a bearer super-capability and makes least-authority use and
secret-redaction difficult.

### Adapter-owned ambient credentials

Rejected. Call sites cannot review which operation is authorized, tests cannot
substitute transports cleanly, and credential leakage becomes adapter-specific.

### A generic capability byte string plus runtime permission enum

Rejected for the core interface. Compile-time right-specific types make
authority confusion harder and keep forbidden operations out of an adapter's
available inputs.

## Consequences

- The memory transport must model rights even when it needs no network secret.
- Provider and rendezvous protocols must specify how each capability is issued,
  rotated, revoked, and serialized.
- Acknowledgement cannot be authorized by an untrusted `DeliveryId` alone.
- Logging and error tests must prove that capability bytes never appear.
