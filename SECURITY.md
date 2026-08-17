# Security policy

Session Chat 2.0 is a protocol laboratory. It has no production release and is
not suitable for protecting real conversations. The current code proves only
the properties listed as implemented in
[`docs/INDEPENDENT_AUDIT_BRIEF.md`](docs/INDEPENDENT_AUDIT_BRIEF.md).

## Supported scope

Security reports should target the current `master` branch or an open pull
request. The retired v1 implementation is preserved under the `legacy-v1` tag
for historical evidence and is not supported.

Especially useful reports include:

- a bypass of an implemented parser, size bound, signature check, or invitation
  lifecycle invariant;
- a contradiction between code, tests, the threat model, and an accepted ADR;
- secret disclosure through an error, log, fixture, serialized object, or CI
  artifact;
- a dependency or build-workflow compromise path; or
- evidence that a proposed security contract cannot be implemented safely.

Design omissions that are already marked unimplemented or deferred are welcome
as architecture feedback, but are not vulnerabilities in a deployed product.

## Reporting

Use GitHub's private vulnerability-reporting form under **Security → Advisories
→ Report a vulnerability** when it is available. Do not publish exploit details
in a public issue. If the private form is unavailable, contact the repository
owner through GitHub to arrange a private channel and share only a non-sensitive
summary until that channel is established.

Include the inspected commit, affected files, preconditions, impact, a minimal
reproduction, and whether the issue applies to implemented code or a future
contract. Never include real credentials, invitation capabilities, mailbox
rights, private keys, or conversation data.

Receipt and remediation timelines are not yet promised. A production release
is blocked on establishing an operated private reporting channel and a published
response policy.
