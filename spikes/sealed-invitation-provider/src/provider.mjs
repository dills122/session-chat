import { closedObject, boundedString, isCanonicalBase64url, normalizeEnvelope, boundedJsonSnapshot } from './validation.mjs';
import { createHash, generateKeyPairSync, randomBytes, sign, timingSafeEqual, verify } from 'node:crypto';
import { capabilityDigest, PADDED_PLAINTEXT_BYTES, PROTOCOL, randomCapability } from './crypto.mjs';

const DEFAULT_MAILBOX_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const DEFAULT_MAX_QUEUE_DEPTH = 16;
const DEFAULT_MAX_LIFETIME_DEPOSITS = 64;
const MAX_SERIALIZED_OVERHEAD_BYTES = 2048;
const X25519_SPKI_BYTES = 44;
const DELIVERY_ID_BYTES = 16;
const DIRECTORY_RECORD_VERSION = 1;
const DIRECTORY_RECORD_FIELDS = [
  'version',
  'directoryKey',
  'bundle',
  'addressAttestation',
  'continuitySignature',
  'issuedAt',
  'expiresAt',
  'signature'
];
const ENVELOPE_DIGEST_FIELDS = [
  'version',
  'mailboxId',
  'envelopeId',
  'expiresAt',
  'ephemeralPublicKey',
  'salt',
  'nonce',
  'ciphertext',
  'authenticationTag'
];
const RECEIVE_BUNDLE_FIELDS = [
  'version',
  'generation',
  'previousBundleDigest',
  'mailboxId',
  'recipientPublicKey',
  'expiresAt'
];

export function normalizeReceiveBundle(bundle) {
  const normalized = closedObject(bundle, RECEIVE_BUNDLE_FIELDS);
  if (!normalized) return undefined;
  if (
    normalized.version !== 1 ||
    !Number.isSafeInteger(normalized.generation) ||
    normalized.generation <= 0 ||
    !(
      (normalized.generation === 1 && normalized.previousBundleDigest === null) ||
      (normalized.generation > 1 &&
        isCanonicalBase64url(normalized.previousBundleDigest, 32))
    ) ||
    !isCanonicalBase64url(normalized.mailboxId, 32) ||
    !isCanonicalBase64url(normalized.recipientPublicKey, X25519_SPKI_BYTES) ||
    !Number.isSafeInteger(normalized.expiresAt)
  ) {
    return undefined;
  }
  return normalized;
}

function canonicalBundle(directoryKey, bundle) {
  return Buffer.from(
    JSON.stringify([
      directoryKey,
      bundle.version,
      bundle.generation,
      bundle.previousBundleDigest,
      bundle.mailboxId,
      bundle.recipientPublicKey,
      bundle.expiresAt
    ])
  );
}

// Deterministic encoding for the bounded snapshots this spike signs. Object
// keys are sorted so a re-encoded record produces the same claim bytes.
function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error('invalid canonical claim');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(',')}]`;
  }
  if (!value || typeof value !== 'object') throw new Error('invalid canonical claim');
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new Error('invalid canonical claim');
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

// One closed DirectoryRecordV1 claims projection. Everything the directory
// stores or returns is signed here, including the complete address attestation
// and any continuity signature, so no field can be swapped after issuance.
function canonicalRecordClaims(claims) {
  return Buffer.from(
    canonicalJson([
      `${PROTOCOL}/directory-record-claims`,
      claims.version,
      claims.directoryKey,
      [
        claims.bundle.version,
        claims.bundle.generation,
        claims.bundle.previousBundleDigest,
        claims.bundle.mailboxId,
        claims.bundle.recipientPublicKey,
        claims.bundle.expiresAt
      ],
      claims.addressAttestation,
      claims.continuitySignature,
      claims.issuedAt,
      claims.expiresAt
    ])
  );
}

function envelopeDigest(envelope) {
  return createHash('sha256')
    .update(
      Buffer.from(
        JSON.stringify([
          `${PROTOCOL}/envelope-idempotency`,
          ...ENVELOPE_DIGEST_FIELDS.map((field) => envelope[field])
        ])
      )
    )
    .digest('base64url');
}

export function bundleDigest(bundle) {
  const normalized = normalizeReceiveBundle(bundle);
  if (!normalized) throw new Error('invalid receive bundle');
  return createHash('sha256').update(canonicalBundle('', normalized)).digest('base64url');
}

export function isSuccessorBundle(previous, candidate) {
  const normalizedPrevious = normalizeReceiveBundle(previous);
  const normalizedCandidate = normalizeReceiveBundle(candidate);
  if (!normalizedPrevious || !normalizedCandidate) return false;
  return (
    normalizedCandidate.generation === normalizedPrevious.generation + 1 &&
    normalizedCandidate.previousBundleDigest === bundleDigest(normalizedPrevious)
  );
}

function canAppendBundle(current, candidate) {
  return (
    (!current && candidate.generation === 1) ||
    (current && isSuccessorBundle(current.bundle, candidate))
  );
}

function genericAuthorizationError() {
  return new Error('mailbox unavailable');
}

function capabilityMatches(expectedDigest, capability) {
  if (typeof capability !== 'string' || capability.length === 0 || capability.length > 128) {
    return false;
  }
  const expected = Buffer.from(expectedDigest, 'base64url');
  const actual = Buffer.from(capabilityDigest(capability), 'base64url');
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

export class InvitationDirectory {
  #records = new Map();
  #signingKey;
  #verificationKey;
  #authorizeRegistration;
  #now;

  constructor({ authorizeRegistration = async () => false, now = Date.now } = {}) {
    const keys = generateKeyPairSync('ed25519');
    this.#signingKey = keys.privateKey;
    this.#verificationKey = keys.publicKey;
    this.#authorizeRegistration = authorizeRegistration;
    this.#now = now;
  }

  async register({ directoryKey, bundle, registrationProof, continuitySignature = null }) {
    const bundleSnapshot = normalizeReceiveBundle(bundle);
    if (
      typeof directoryKey !== 'string' ||
      directoryKey.length === 0 ||
      directoryKey.length > 256 ||
      !bundleSnapshot ||
      bundleSnapshot.expiresAt <= this.#now() ||
      !registrationProof || typeof registrationProof !== 'object' || Array.isArray(registrationProof) ||
      !(continuitySignature === null || isCanonicalBase64url(continuitySignature, 64))
    ) {
      throw new Error('invalid directory registration');
    }
    let registrationProofSnapshot;
    try { registrationProofSnapshot = boundedJsonSnapshot(registrationProof); }
    catch { throw new Error('invalid directory registration'); }
    const current = this.#records.get(directoryKey);
    if (!canAppendBundle(current, bundleSnapshot)) {
      throw new Error('directory rotation chain mismatch');
    }
    if (
      !(await this.#authorizeRegistration({
        directoryKey,
        bundle: structuredClone(bundleSnapshot),
        registrationProof: structuredClone(registrationProofSnapshot)
      }))
    ) {
      throw new Error('directory registration rejected');
    }

    // Authorization is asynchronous. Recheck the predecessor after it returns
    // so two competing successors cannot both commit in this in-process model.
    // Production still requires a durable database compare-and-swap transaction.
    const latest = this.#records.get(directoryKey);
    if (bundleSnapshot.expiresAt <= this.#now()) {
      throw new Error('invalid directory registration');
    }
    if (!canAppendBundle(latest, bundleSnapshot)) {
      throw new Error('directory rotation chain mismatch');
    }

    const claims = {
      version: DIRECTORY_RECORD_VERSION,
      directoryKey,
      bundle: bundleSnapshot,
      addressAttestation: registrationProofSnapshot,
      continuitySignature,
      issuedAt: this.#now(),
      expiresAt: bundleSnapshot.expiresAt
    };
    const signature = sign(null, canonicalRecordClaims(claims), this.#signingKey).toString('base64url');
    const record = { ...claims, signature };
    this.#records.set(directoryKey, record);
    return structuredClone(record);
  }

  lookup(directoryKey) {
    if (!boundedString(directoryKey, 256)) return undefined;
    const record = this.#records.get(directoryKey);
    if (!record || !this.#live(record)) {
      return undefined;
    }
    return structuredClone(record);
  }

  // Authenticity and freshness together. A record whose mailbox has expired is
  // no longer accepted routing material even though its signature still checks.
  verifyRecord(record) {
    try {
      const claims = this.#normalizeRecord(record);
      if (!claims || !this.#live(claims)) return false;
      return verify(
        null,
        canonicalRecordClaims(claims),
        this.#verificationKey,
        Buffer.from(claims.signature, 'base64url')
      );
    } catch {
      return false;
    }
  }

  // Single record-acceptance API: closed shape, signature, expected lookup key
  // and freshness. Returns the normalized record, or undefined on any failure.
  acceptRecord({ record, expectedDirectoryKey } = {}) {
    if (!boundedString(expectedDirectoryKey, 256)) return undefined;
    let claims;
    try {
      claims = this.#normalizeRecord(record);
    } catch {
      return undefined;
    }
    if (!claims || claims.directoryKey !== expectedDirectoryKey) return undefined;
    if (!this.verifyRecord(record)) return undefined;
    return structuredClone(claims);
  }

  #live(claims) {
    const now = this.#now();
    return claims.expiresAt > now && claims.bundle.expiresAt > now;
  }

  #normalizeRecord(record) {
    const normalized = closedObject(record, DIRECTORY_RECORD_FIELDS);
    if (
      !normalized ||
      normalized.version !== DIRECTORY_RECORD_VERSION ||
      !boundedString(normalized.directoryKey, 256) ||
      !isCanonicalBase64url(normalized.signature, 64) ||
      !Number.isSafeInteger(normalized.issuedAt) ||
      !Number.isSafeInteger(normalized.expiresAt) ||
      normalized.issuedAt > normalized.expiresAt ||
      !(normalized.continuitySignature === null || isCanonicalBase64url(normalized.continuitySignature, 64))
    ) {
      return undefined;
    }
    const bundle = normalizeReceiveBundle(normalized.bundle);
    if (!bundle || normalized.expiresAt > bundle.expiresAt) return undefined;
    let addressAttestation;
    try {
      addressAttestation = boundedJsonSnapshot(normalized.addressAttestation);
    } catch {
      return undefined;
    }
    return { ...normalized, bundle, addressAttestation };
  }

  inspectRecordForSpike(directoryKey) {
    return structuredClone(this.#records.get(directoryKey));
  }
}

export class InvitationMailboxService {
  #mailboxes = new Map();
  #now;
  #mailboxTtlMs;
  #maxQueueDepth;
  #maxLifetimeDeposits;

  constructor({
    now = Date.now,
    mailboxTtlMs = DEFAULT_MAILBOX_TTL_MS,
    maxQueueDepth = DEFAULT_MAX_QUEUE_DEPTH,
    maxLifetimeDeposits = DEFAULT_MAX_LIFETIME_DEPOSITS
  } = {}) {
    this.#now = now;
    this.#mailboxTtlMs = mailboxTtlMs;
    this.#maxQueueDepth = maxQueueDepth;
    this.#maxLifetimeDeposits = maxLifetimeDeposits;
  }

  createMailbox({ recipientPublicKey, generation = 1, previousBundleDigest = null }) {
    if (!isCanonicalBase64url(recipientPublicKey, X25519_SPKI_BYTES)) {
      throw new Error('recipient public key is required');
    }

    const mailboxId = randomBytes(32).toString('base64url');
    const readCapability = randomCapability();
    const acknowledgementCapability = randomCapability();
    const expiresAt = this.#now() + this.#mailboxTtlMs;
    this.#mailboxes.set(mailboxId, {
      readCapabilityDigest: capabilityDigest(readCapability),
      acknowledgementCapabilityDigest: capabilityDigest(acknowledgementCapability),
      expiresAt,
      queue: [],
      deliveriesByEnvelopeId: new Map(),
      acceptedEnvelopeCount: 0
    });

    return {
      bundle: {
        version: 1,
        generation,
        previousBundleDigest,
        mailboxId,
        recipientPublicKey,
        expiresAt
      },
      readCapability,
      acknowledgementCapability
    };
  }

  deposit({ mailboxId, envelope }) {
    envelope = normalizeEnvelope(envelope);
    const mailbox = this.#liveMailbox(mailboxId);
    if (!mailbox || !envelope || envelope.mailboxId !== mailboxId) {
      throw genericAuthorizationError();
    }
    if (
      !Number.isSafeInteger(envelope.expiresAt) ||
      envelope.expiresAt <= this.#now() ||
      envelope.expiresAt > mailbox.expiresAt
    ) {
      throw new Error('invalid envelope expiry');
    }

    const serializedBytes = Buffer.byteLength(JSON.stringify(envelope));
    if (serializedBytes > PADDED_PLAINTEXT_BYTES + MAX_SERIALIZED_OVERHEAD_BYTES) {
      throw new Error('envelope exceeds mailbox size limit');
    }

    // Idempotency is per immutable delivery request, not per identifier. A retry
    // that changes any authenticated field is a conflict, never a silent success
    // for bytes the recipient will never receive.
    const digest = envelopeDigest(envelope);
    const priorDelivery = mailbox.deliveriesByEnvelopeId.get(envelope.envelopeId);
    if (priorDelivery) {
      const expected = Buffer.from(priorDelivery.digest, 'base64url');
      const actual = Buffer.from(digest, 'base64url');
      if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
        throw new Error('envelope idempotency conflict');
      }
      return { deliveryId: priorDelivery.deliveryId, duplicate: true };
    }

    this.#purgeExpiredEnvelopes(mailbox);
    if (mailbox.acceptedEnvelopeCount >= this.#maxLifetimeDeposits) {
      throw new Error('mailbox lifetime deposit limit reached');
    }
    if (mailbox.queue.length >= this.#maxQueueDepth) {
      throw new Error('mailbox queue limit reached');
    }

    const deliveryId = randomBytes(16).toString('base64url');
    mailbox.queue.push({
      deliveryId,
      envelope: structuredClone(envelope)
    });
    mailbox.deliveriesByEnvelopeId.set(envelope.envelopeId, { deliveryId, digest });
    mailbox.acceptedEnvelopeCount += 1;
    return { deliveryId, duplicate: false };
  }

  fetch({ mailboxId, readCapability }) {
    const mailbox = this.#authorizedMailbox(
      mailboxId,
      readCapability,
      'readCapabilityDigest'
    );
    this.#purgeExpiredEnvelopes(mailbox);
    return structuredClone(mailbox.queue);
  }

  acknowledge({ mailboxId, acknowledgementCapability, deliveryIds }) {
    if (
      !Array.isArray(deliveryIds) ||
      deliveryIds.length === 0 ||
      deliveryIds.length > this.#maxQueueDepth ||
      deliveryIds.some((deliveryId) => !isCanonicalBase64url(deliveryId, DELIVERY_ID_BYTES))
    ) {
      throw new Error('invalid acknowledgement request');
    }
    const mailbox = this.#authorizedMailbox(
      mailboxId,
      acknowledgementCapability,
      'acknowledgementCapabilityDigest'
    );
    const acknowledged = new Set(deliveryIds);
    mailbox.queue = mailbox.queue.filter((delivery) => !acknowledged.has(delivery.deliveryId));
  }

  inspectMailboxForSpike(mailboxId) {
    const mailbox = this.#mailboxes.get(mailboxId);
    if (!mailbox) return undefined;
    return {
      expiresAt: mailbox.expiresAt,
      queue: structuredClone(mailbox.queue),
      seenEnvelopeIds: [...mailbox.deliveriesByEnvelopeId.keys()],
      acceptedEnvelopeCount: mailbox.acceptedEnvelopeCount
    };
  }

  #liveMailbox(mailboxId) {
    if (!isCanonicalBase64url(mailboxId, 32)) return undefined;
    const mailbox = this.#mailboxes.get(mailboxId);
    if (!mailbox || mailbox.expiresAt <= this.#now()) {
      this.#mailboxes.delete(mailboxId);
      return undefined;
    }
    return mailbox;
  }

  #authorizedMailbox(mailboxId, capability, capabilityDigestField) {
    const mailbox = this.#liveMailbox(mailboxId);
    if (!mailbox || !capabilityMatches(mailbox[capabilityDigestField], capability)) {
      throw genericAuthorizationError();
    }
    return mailbox;
  }

  #purgeExpiredEnvelopes(mailbox) {
    mailbox.queue = mailbox.queue.filter(({ envelope }) => envelope.expiresAt > this.#now());
  }
}
