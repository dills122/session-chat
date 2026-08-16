import { generateKeyPairSync, sign, verify } from 'node:crypto';
import { bundleDigest } from './provider.mjs';

const DEFAULT_ATTESTATION_TTL_MS = 60 * 60 * 1000;

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
    if (
      typeof directoryKey !== 'string' ||
      directoryKey.length === 0 ||
      directoryKey.length > 256 ||
      !bundle ||
      !Number.isSafeInteger(bundle.expiresAt) ||
      bundle.expiresAt <= this.#now()
    ) {
      throw new Error('invalid address attestation request');
    }
    if (
      !(await this.#authorizeAddressControl({
        directoryKey,
        bundle,
        addressControlProof
      }))
    ) {
      throw new Error('address control proof rejected');
    }

    const issuedAt = this.#now();
    const unsigned = {
      version: 1,
      issuer: this.#issuer,
      directoryKey,
      receiveBundleDigest: bundleDigest(bundle),
      issuedAt,
      expiresAt: Math.min(bundle.expiresAt, issuedAt + this.#attestationTtlMs)
    };
    const signature = sign(
      null,
      canonicalAttestation(unsigned),
      this.#signingKey
    ).toString('base64url');
    return { ...unsigned, signature };
  }

  verify({ directoryKey, bundle, attestation }) {
    try {
      if (
        attestation?.version !== 1 ||
        attestation.issuer !== this.#issuer ||
        attestation.directoryKey !== directoryKey ||
        attestation.receiveBundleDigest !== bundleDigest(bundle) ||
        !Number.isSafeInteger(attestation.issuedAt) ||
        !Number.isSafeInteger(attestation.expiresAt) ||
        attestation.issuedAt > this.#now() ||
        attestation.expiresAt <= this.#now() ||
        attestation.expiresAt > bundle.expiresAt
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
