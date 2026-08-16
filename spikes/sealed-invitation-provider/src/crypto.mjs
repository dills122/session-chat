import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  randomUUID
} from 'node:crypto';

export const PROTOCOL = 'session-chat-sealed-invitation-spike-v1';
export const PADDED_PLAINTEXT_BYTES = 1024;

const KEY_BYTES = 32;
const NONCE_BYTES = 12;
const SALT_BYTES = 32;
const LENGTH_PREFIX_BYTES = 4;

function encode(value) {
  return Buffer.from(value).toString('base64url');
}

function decode(value) {
  return Buffer.from(value, 'base64url');
}

function importPublicKey(value) {
  return createPublicKey({
    key: decode(value),
    format: 'der',
    type: 'spki'
  });
}

function importPrivateKey(value) {
  return createPrivateKey({
    key: decode(value),
    format: 'der',
    type: 'pkcs8'
  });
}

function associatedData(envelope) {
  return Buffer.from(
    JSON.stringify([PROTOCOL, envelope.version, envelope.mailboxId, envelope.envelopeId, envelope.expiresAt])
  );
}

function paddedPlaintext(invitation) {
  const content = Buffer.from(
    JSON.stringify({
      type: 'session-chat-invitation',
      invitation
    })
  );

  const maximumContentBytes = PADDED_PLAINTEXT_BYTES - LENGTH_PREFIX_BYTES;
  if (content.length > maximumContentBytes) {
    throw new Error('invitation exceeds the fixed-size envelope limit');
  }

  const output = randomBytes(PADDED_PLAINTEXT_BYTES);
  output.writeUInt32BE(content.length, 0);
  content.copy(output, LENGTH_PREFIX_BYTES);
  return output;
}

function unpadPlaintext(value) {
  if (value.length !== PADDED_PLAINTEXT_BYTES) {
    throw new Error('invalid padded invitation size');
  }

  const contentLength = value.readUInt32BE(0);
  const maximumContentBytes = PADDED_PLAINTEXT_BYTES - LENGTH_PREFIX_BYTES;
  if (contentLength > maximumContentBytes) {
    throw new Error('invalid invitation content length');
  }

  const parsed = JSON.parse(
    value.subarray(LENGTH_PREFIX_BYTES, LENGTH_PREFIX_BYTES + contentLength).toString('utf8')
  );

  if (parsed?.type !== 'session-chat-invitation' || !parsed.invitation) {
    throw new Error('invalid invitation payload');
  }

  return parsed.invitation;
}

export function generateReceiveKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  return {
    publicKey: encode(publicKey.export({ format: 'der', type: 'spki' })),
    privateKey: encode(privateKey.export({ format: 'der', type: 'pkcs8' }))
  };
}

export function randomCapability() {
  return encode(randomBytes(32));
}

export function capabilityDigest(capability) {
  return createHash('sha256').update(capability).digest('base64url');
}

export function sealInvitation({ recipientPublicKey, mailboxId, invitation, expiresAt, now = Date.now() }) {
  if (!mailboxId || !recipientPublicKey) {
    throw new Error('mailbox and recipient public key are required');
  }
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= now) {
    throw new Error('invitation expiry must be in the future');
  }

  const ephemeral = generateKeyPairSync('x25519');
  const sharedSecret = diffieHellman({
    privateKey: ephemeral.privateKey,
    publicKey: importPublicKey(recipientPublicKey)
  });
  const salt = randomBytes(SALT_BYTES);
  const key = Buffer.from(hkdfSync('sha256', sharedSecret, salt, Buffer.from(PROTOCOL), KEY_BYTES));
  const nonce = randomBytes(NONCE_BYTES);
  const envelope = {
    version: 1,
    mailboxId,
    envelopeId: randomUUID(),
    expiresAt,
    ephemeralPublicKey: encode(ephemeral.publicKey.export({ format: 'der', type: 'spki' })),
    salt: encode(salt),
    nonce: encode(nonce)
  };

  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(associatedData(envelope));
  const ciphertext = Buffer.concat([cipher.update(paddedPlaintext(invitation)), cipher.final()]);

  return {
    ...envelope,
    ciphertext: encode(ciphertext),
    authenticationTag: encode(cipher.getAuthTag())
  };
}

export function openInvitation({ recipientPrivateKey, envelope, expectedMailboxId, now = Date.now() }) {
  if (envelope.version !== 1 || envelope.mailboxId !== expectedMailboxId) {
    throw new Error('invitation envelope context mismatch');
  }
  if (!Number.isSafeInteger(envelope.expiresAt) || envelope.expiresAt <= now) {
    throw new Error('invitation envelope expired');
  }

  const sharedSecret = diffieHellman({
    privateKey: importPrivateKey(recipientPrivateKey),
    publicKey: importPublicKey(envelope.ephemeralPublicKey)
  });
  const key = Buffer.from(
    hkdfSync('sha256', sharedSecret, decode(envelope.salt), Buffer.from(PROTOCOL), KEY_BYTES)
  );
  const decipher = createDecipheriv('aes-256-gcm', key, decode(envelope.nonce));
  decipher.setAAD(associatedData(envelope));
  decipher.setAuthTag(decode(envelope.authenticationTag));

  const plaintext = Buffer.concat([decipher.update(decode(envelope.ciphertext)), decipher.final()]);
  return unpadPlaintext(plaintext);
}
