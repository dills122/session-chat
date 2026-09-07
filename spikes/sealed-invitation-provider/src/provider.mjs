import { closedObject, boundedString, isCanonicalBase64url, normalizeEnvelope, boundedJsonSnapshot } from './validation.mjs';
import { createHash, generateKeyPairSync, randomBytes, sign, timingSafeEqual, verify } from 'node:crypto';
import { capabilityDigest, PADDED_PLAINTEXT_BYTES, randomCapability } from './crypto.mjs';

const DEFAULT_MAILBOX_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const DEFAULT_MAX_QUEUE_DEPTH = 16;
const DEFAULT_MAX_LIFETIME_DEPOSITS = 64;
const MAX_SERIALIZED_OVERHEAD_BYTES = 2048;
const X25519_SPKI_BYTES = 44;
const DELIVERY_ID_BYTES = 16;
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

  async register({ directoryKey, bundle, registrationProof }) {
    const bundleSnapshot = normalizeReceiveBundle(bundle);
    if (
      typeof directoryKey !== 'string' ||
      directoryKey.length === 0 ||
      directoryKey.length > 256 ||
      !bundleSnapshot ||
      bundleSnapshot.expiresAt <= this.#now() ||
      !registrationProof || typeof registrationProof !== 'object' || Array.isArray(registrationProof)
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

    const signature = sign(
      null,
      canonicalBundle(directoryKey, bundleSnapshot),
      this.#signingKey
    ).toString('base64url');
    const record = {
      directoryKey,
      bundle: bundleSnapshot,
      addressAttestation: registrationProofSnapshot,
      signature
    };
    this.#records.set(directoryKey, record);
    return structuredClone(record);
  }

  lookup(directoryKey) {
    if (!boundedString(directoryKey, 256)) return undefined;
    const record = this.#records.get(directoryKey);
    if (!record || record.bundle.expiresAt <= this.#now()) {
      return undefined;
    }
    return structuredClone(record);
  }

  verifyRecord(record) {
    try {
      record = closedObject(record, ['directoryKey', 'bundle', 'addressAttestation', 'signature']);
      if (!record || !boundedString(record.directoryKey, 256) || !isCanonicalBase64url(record.signature, 64)) return false;
      boundedJsonSnapshot(record.addressAttestation);
      const normalizedBundle = normalizeReceiveBundle(record.bundle);
      if (!normalizedBundle) return false;
      return verify(
        null,
        canonicalBundle(record.directoryKey, normalizedBundle),
        this.#verificationKey,
        Buffer.from(record.signature, 'base64url')
      );
    } catch {
      return false;
    }
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

    const priorDelivery = mailbox.deliveriesByEnvelopeId.get(envelope.envelopeId);
    if (priorDelivery) {
      return { deliveryId: priorDelivery, duplicate: true };
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
    mailbox.deliveriesByEnvelopeId.set(envelope.envelopeId, deliveryId);
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
