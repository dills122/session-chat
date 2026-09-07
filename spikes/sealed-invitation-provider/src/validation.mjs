// Object API boundary for this in-process spike. A future byte transport must
// also cap its input before JSON parsing. Never invoke caller accessors/toJSON.
export function closedObject(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return undefined;
  const result = {};
  for (const key of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) return undefined;
    Object.defineProperty(result, key, { value: descriptor.value, enumerable: true });
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.length || keys.some((key) => !fields.includes(key))) return undefined;
  return result;
}

export function boundedString(value, maximum) {
  // Preserve the spike's UTF-16 code-unit limits. UTF-8 expansion is bounded
  // by three bytes per code unit; no full-string scan is needed here.
  return typeof value === 'string' && value.length > 0 && value.length <= maximum;
}

export function isCanonicalBase64url(value, expectedBytes) {
  if (typeof value !== 'string' || value.length !== Math.ceil(expectedBytes * 4 / 3) ||
      !/^[A-Za-z0-9_-]+$/.test(value)) return false;
  const bytes = Buffer.from(value, 'base64url');
  return bytes.length === expectedBytes && bytes.toString('base64url') === value;
}

export function normalizeEnvelope(value) {
  const envelope = closedObject(value, ['version', 'mailboxId', 'envelopeId', 'expiresAt',
    'ephemeralPublicKey', 'salt', 'nonce', 'ciphertext', 'authenticationTag']);
  if (!envelope || envelope.version !== 1 || !isCanonicalBase64url(envelope.mailboxId, 32) ||
      !boundedString(envelope.envelopeId, 64) || !Number.isSafeInteger(envelope.expiresAt) ||
      !isCanonicalBase64url(envelope.ephemeralPublicKey, 44) ||
      !isCanonicalBase64url(envelope.salt, 32) || !isCanonicalBase64url(envelope.nonce, 12) ||
      !isCanonicalBase64url(envelope.ciphertext, 1024) ||
      !isCanonicalBase64url(envelope.authenticationTag, 16)) return undefined;
  return envelope;
}

export function normalizeAttestation(value) {
  const result = closedObject(value, ['version', 'issuer', 'directoryKey', 'receiveBundleDigest',
    'issuedAt', 'expiresAt', 'signature']);
  if (!result || result.version !== 1 || !boundedString(result.issuer, 256) ||
      !boundedString(result.directoryKey, 256) || !isCanonicalBase64url(result.receiveBundleDigest, 32) ||
      !Number.isSafeInteger(result.issuedAt) || !Number.isSafeInteger(result.expiresAt) ||
      !isCanonicalBase64url(result.signature, 64)) return undefined;
  return result;
}

export function boundedJsonSnapshot(value, maximumBytes = 8192) {
  const seen = new WeakSet();
  let entries = 0;
  function visit(item, depth) {
    if (depth > 4) throw new Error('invalid bounded object');
    if (item === null || typeof item === 'boolean') return item;
    if (typeof item === 'number' && Number.isSafeInteger(item)) return item;
    if (typeof item === 'string' && item.length <= Math.min(maximumBytes, 4096) && Buffer.byteLength(item) <= Math.min(maximumBytes, 4096)) return item;
    if (!item || typeof item !== 'object' || seen.has(item)) throw new Error('invalid bounded object');
    const array = Array.isArray(item);
    if (!array && ![Object.prototype, null].includes(Object.getPrototypeOf(item))) throw new Error('invalid bounded object');
    seen.add(item);
    const keys = Reflect.ownKeys(item);
    const output = array ? [] : Object.create(null);
    if (array && (item.length > 32 || keys.length !== item.length + 1)) throw new Error('invalid bounded object');
    for (const key of keys) {
      if (array && key === 'length') continue;
      if (++entries > 32 || typeof key !== 'string' || key.length > 64) throw new Error('invalid bounded object');
      const descriptor = Object.getOwnPropertyDescriptor(item, key);
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) throw new Error('invalid bounded object');
      if (array && key !== String(output.length)) throw new Error('invalid bounded object');
      Object.defineProperty(output, key, { value: visit(descriptor.value, depth + 1), enumerable: true });
    }
    return output;
  }
  const snapshot = visit(value, 0);
  if (Buffer.byteLength(JSON.stringify(snapshot)) > maximumBytes) throw new Error('invalid bounded object');
  return snapshot;
}
