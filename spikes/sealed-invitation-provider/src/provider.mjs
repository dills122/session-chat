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

function isCanonicalBase64url(value, expectedBytes) {
  if (typeof value !== 'string' || value.length === 0 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    return false;
  }
  const decoded = Buffer.from(value, 'base64url');
  return decoded.length === expectedBytes && decoded.toString('base64url') === value;
}

function isValidBundle(bundle) {
  return (
    bundle?.version === 1 &&
    Number.isSafeInteger(bundle.generation) &&
    bundle.generation > 0 &&
    ((bundle.generation === 1 && bundle.previousBundleDigest === null) ||
      (bundle.generation > 1 && isCanonicalBase64url(bundle.previousBundleDigest, 32))) &&
    isCanonicalBase64url(bundle.mailboxId, 32) &&
    isCanonicalBase64url(bundle.recipientPublicKey, X25519_SPKI_BYTES) &&
    Number.isSafeInteger(bundle.expiresAt)
  );
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
  return createHash('sha256').update(canonicalBundle('', bundle)).digest('base64url');
}

export function isSuccessorBundle(previous, candidate) {
  return (
    candidate.generation === previous.generation + 1 &&
    candidate.previousBundleDigest === bundleDigest(previous)
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
    if (
      typeof directoryKey !== 'string' ||
      directoryKey.length === 0 ||
      directoryKey.length > 256 ||
      !isValidBundle(bundle) ||
      bundle.expiresAt <= this.#now()
    ) {
      throw new Error('invalid directory registration');
    }
    const current = this.#records.get(directoryKey);
    if ((!current && bundle.generation !== 1) || (current && !isSuccessorBundle(current.bundle, bundle))) {
      throw new Error('directory rotation chain mismatch');
    }
    if (
      !(await this.#authorizeRegistration({
        directoryKey,
        bundle,
        registrationProof
      }))
    ) {
      throw new Error('directory registration rejected');
    }

    const signature = sign(null, canonicalBundle(directoryKey, bundle), this.#signingKey).toString(
      'base64url'
    );
    const record = {
      directoryKey,
      bundle: structuredClone(bundle),
      addressAttestation: structuredClone(registrationProof),
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
      return verify(
        null,
        canonicalBundle(record.directoryKey, record.bundle),
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
    const expiresAt = this.#now() + this.#mailboxTtlMs;
    this.#mailboxes.set(mailboxId, {
      readCapabilityDigest: capabilityDigest(readCapability),
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
      readCapability
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
    const mailbox = this.#authorizedMailbox(mailboxId, readCapability);
    this.#purgeExpiredEnvelopes(mailbox);
    return structuredClone(mailbox.queue);
  }

  acknowledge({ mailboxId, readCapability, deliveryIds }) {
    const mailbox = this.#authorizedMailbox(mailboxId, readCapability);
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

  #authorizedMailbox(mailboxId, readCapability) {
    const mailbox = this.#liveMailbox(mailboxId);
    if (!mailbox || !capabilityMatches(mailbox.readCapabilityDigest, readCapability)) {
      throw genericAuthorizationError();
    }
    return mailbox;
  }

  #purgeExpiredEnvelopes(mailbox) {
    mailbox.queue = mailbox.queue.filter(({ envelope }) => envelope.expiresAt > this.#now());
  }
}
