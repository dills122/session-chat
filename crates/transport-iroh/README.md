# transport-iroh

`transport-iroh` is the bounded authenticated online link for Session Chat's
explicit FastV1 experiment. It pins Iroh 1.1.0, uses the AWS-LC TLS provider,
and carries nonempty length-prefixed frames under caller-owned size and time
bounds.

Two modes are intentionally separate:

- `bind_loopback` uses Iroh's minimal preset with one exact loopback address,
  no relay, and no address lookup. Retained tests use this mode.
- `bind_public` uses Iroh's N0 preset. It may use direct connections, relay
  forwarding, address lookup, DNS, NAT discovery, and port mapping. Callers
  must label it Fast and disclose that metadata observer set.

This crate does not provide offline storage, mailbox issuance, cursor
persistence, acknowledgement durability, rotation, anonymity, or a complete
`EnvelopeDelivery` implementation. Iroh endpoint authentication also does not
authorize Session Chat admission or MLS membership.

Official API sources:

- <https://docs.rs/iroh/1.1.0/iroh/#examples>
- <https://docs.rs/iroh/1.1.0/iroh/#encryption>
- <https://docs.rs/iroh/1.1.0/iroh/#relay-servers>
- <https://docs.rs/iroh/1.1.0/iroh/endpoint/struct.RecvStream.html#method.read_to_end>
