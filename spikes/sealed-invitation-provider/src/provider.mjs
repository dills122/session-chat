import { createHash, generateKeyPairSync, randomBytes, sign, timingSafeEqual, verify } from 'node:crypto';
import { capabilityDigest, PADDED_PLAINTEXT_BYTES, randomCapability } from './crypto.mjs';

const DEFAULT_MAILBOX_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const DEFAULT_MAX_QUEUE_DEPTH = 16;
const DEFAULT_MAX_LIFETIME_DEPOSITS = 64;
const MAX_SERIALIZED_OVERHEAD_BYTES = 2048;
const X25519_SPKI_BYTES = 44;
const AES_GCM_TAG_BYTES = 16;
const AES_GCM_NONCE_BYTES = 12;
const HKDF_SALT_BYTES = 32;
const DELIVERY_ID_BYTES = 16;
const MAX_REGISTRATION_PROOF_BYTES = 8192;
const MAX_REGISTRATION_PROOF_DEPTH = 4;
const MAX_REGISTRATION_PROOF_ENTRIES = 32;
const MAX_REGISTRATION_PROOF_STRING_BYTES = 4096;
const RECEIVE_BUNDLE_FIELDS = [
  'version',
  'generation',
  'previousBundleDigest',
  'mailboxId',
  'recipientPublicKey',
  'expiresAt'
];

function isCanonicalBase64url(value, expectedBytes) {
  if (typeof value !== 'string' || value.length === 0 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    return false;
  }
  const decoded = Buffer.from(value, 'base64url');
  return decoded.length === expectedBytes && decoded.toString('base64url') === value;
}

export function normalizeReceiveBundle(bundle) {
  if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle)) return undefined;
  const prototype = Object.getPrototypeOf(bundle);
  if (prototype !== Object.prototype && prototype !== null) return undefined;

  const descriptors = Object.getOwnPropertyDescriptors(bundle);
  const keys = Reflect.ownKeys(descriptors);
  if (
    keys.length !== RECEIVE_BUNDLE_FIELDS.length ||
    RECEIVE_BUNDLE_FIELDS.some((field) => {
      const descriptor = descriptors[field];
      return !descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value');
    }) ||
    keys.some((key) => typeof key !== 'string' || !RECEIVE_BUNDLE_FIELDS.includes(key))
  ) {
    return undefined;
  }

  const normalized = Object.fromEntries(
    RECEIVE_BUNDLE_FIELDS.map((field) => [field, descriptors[field].value])
  );
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

function isValidEnvelopeShape(envelope) {
  return (
    envelope?.version === 1 &&
    typeof envelope.envelopeId === 'string' &&
    envelope.envelopeId.length > 0 &&
    envelope.envelopeId.length <= 64 &&
    isCanonicalBase64url(envelope.ephemeralPublicKey, X25519_SPKI_BYTES) &&
    isCanonicalBase64url(envelope.salt, HKDF_SALT_BYTES) &&
    isCanonicalBase64url(envelope.nonce, AES_GCM_NONCE_BYTES) &&
    isCanonicalBase64url(envelope.ciphertext, PADDED_PLAINTEXT_BYTES) &&
    isCanonicalBase64url(envelope.authenticationTag, AES_GCM_TAG_BYTES)
  );
}

function isBoundedRegistrationProof(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const seen = new WeakSet();
  let entries = 0;
  const visit = (item, depth) => {
    if (depth > MAX_REGISTRATION_PROOF_DEPTH) return false;
    if (item === null || typeof item === 'boolean') return true;
    if (typeof item === 'number') return Number.isSafeInteger(item);
    if (typeof item === 'string') {
      return Buffer.byteLength(item) <= MAX_REGISTRATION_PROOF_STRING_BYTES;
    }
    if (typeof item !== 'object' || seen.has(item)) return false;

    const prototype = Object.getPrototypeOf(item);
    if (!Array.isArray(item) && prototype !== Object.prototype && prototype !== null) {
      return false;
    }
    seen.add(item);
    const childEntries = Array.isArray(item) ? item.entries() : Object.entries(item);
    for (const [key, child] of childEntries) {
      entries += 1;
      if (
        entries > MAX_REGISTRATION_PROOF_ENTRIES ||
        (!Array.isArray(item) && Buffer.byteLength(key) > 64) ||
        !visit(child, depth + 1)
      ) {
        return false;
      }
    }
    return true;
  };

  if (!visit(value, 0)) return false;
  try {
    return Buffer.byteLength(JSON.stringify(value)) <= MAX_REGISTRATION_PROOF_BYTES;
  } catch {
    return false;
  }
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
      !isBoundedRegistrationProof(registrationProof)
    ) {
      throw new Error('invalid directory registration');
    }
    const registrationProofSnapshot = structuredClone(registrationProof);
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
    const record = this.#records.get(directoryKey);
    if (!record || record.bundle.expiresAt <= this.#now()) {
      return undefined;
    }
    return structuredClone(record);
  }

  verifyRecord(record) {
    try {
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
    if (!recipientPublicKey) {
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
    const mailbox = this.#liveMailbox(mailboxId);
    if (!mailbox || envelope?.mailboxId !== mailboxId || !isValidEnvelopeShape(envelope)) {
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
