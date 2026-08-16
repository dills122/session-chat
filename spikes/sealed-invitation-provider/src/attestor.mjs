import { generateKeyPairSync, sign, verify } from 'node:crypto';
import { bundleDigest, normalizeReceiveBundle } from './provider.mjs';

const DEFAULT_ATTESTATION_TTL_MS = 60 * 60 * 1000;
const MAX_ADDRESS_CONTROL_PROOF_BYTES = 4096;

function canonicalAttestation(attestation) {
  return Buffer.from(
    JSON.stringify([
      attestation.version,
      attestation.issuer,
      attestation.directoryKey,
      attestation.receiveBundleDigest,
      attestation.issuedAt,
      attestation.expiresAt
    ])
  );
}

export class AddressAttestor {
  #issuer;
  #signingKey;
  #verificationKey;
  #authorizeAddressControl;
  #now;
  #attestationTtlMs;

  constructor({
    issuer = 'session-chat-address-attestor-spike',
    authorizeAddressControl = async () => false,
    now = Date.now,
    attestationTtlMs = DEFAULT_ATTESTATION_TTL_MS
  } = {}) {
    const keys = generateKeyPairSync('ed25519');
    this.#issuer = issuer;
    this.#signingKey = keys.privateKey;
    this.#verificationKey = keys.publicKey;
    this.#authorizeAddressControl = authorizeAddressControl;
    this.#now = now;
    this.#attestationTtlMs = attestationTtlMs;
  }

  async issue({ directoryKey, bundle, addressControlProof }) {
    const bundleSnapshot = normalizeReceiveBundle(bundle);
    if (
      typeof directoryKey !== 'string' ||
      directoryKey.length === 0 ||
      directoryKey.length > 256 ||
      !bundleSnapshot ||
      bundleSnapshot.expiresAt <= this.#now() ||
      typeof addressControlProof !== 'string' ||
      Buffer.byteLength(addressControlProof) > MAX_ADDRESS_CONTROL_PROOF_BYTES
    ) {
      throw new Error('invalid address attestation request');
    }
    if (
      !(await this.#authorizeAddressControl({
        directoryKey,
        bundle: structuredClone(bundleSnapshot),
        addressControlProof
      }))
    ) {
      throw new Error('address control proof rejected');
    }

    const issuedAt = this.#now();
    if (bundleSnapshot.expiresAt <= issuedAt) {
      throw new Error('invalid address attestation request');
    }
    const unsigned = {
      version: 1,
      issuer: this.#issuer,
      directoryKey,
      receiveBundleDigest: bundleDigest(bundleSnapshot),
      issuedAt,
      expiresAt: Math.min(bundleSnapshot.expiresAt, issuedAt + this.#attestationTtlMs)
    };
    const signature = sign(null, canonicalAttestation(unsigned), this.#signingKey).toString('base64url');
    return { ...unsigned, signature };
  }

  verify({ directoryKey, bundle, attestation }) {
    try {
      const normalizedBundle = normalizeReceiveBundle(bundle);
      if (
        !normalizedBundle ||
        attestation?.version !== 1 ||
        attestation.issuer !== this.#issuer ||
        attestation.directoryKey !== directoryKey ||
        attestation.receiveBundleDigest !== bundleDigest(bundle) ||
        !Number.isSafeInteger(attestation.issuedAt) ||
        !Number.isSafeInteger(attestation.expiresAt) ||
        attestation.issuedAt > this.#now() ||
        attestation.expiresAt <= this.#now() ||
        attestation.expiresAt > normalizedBundle.expiresAt
      ) {
        return false;
      }

      return verify(
        null,
        canonicalAttestation(attestation),
        this.#verificationKey,
        Buffer.from(attestation.signature, 'base64url')
      );
    } catch {
      return false;
    }
  }
}
