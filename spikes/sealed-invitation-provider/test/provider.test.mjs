import assert from 'node:assert/strict';
import test from 'node:test';
import { AddressAttestor } from '../src/attestor.mjs';
import {
  generateReceiveKeyPair,
  openInvitation,
  sealInvitation
} from '../src/crypto.mjs';
import {
  bundleDigest,
  InvitationDirectory,
  InvitationMailboxService
} from '../src/provider.mjs';

function setup({
  maxQueueDepth = 16,
  maxLifetimeDeposits = 64,
  mailboxTtlMs = 60_000
} = {}) {
  let now = 1_700_000_000_000;
  const clock = () => now;
  const recipient = generateReceiveKeyPair();
  const mailboxService = new InvitationMailboxService({
    now: clock,
    mailboxTtlMs,
    maxQueueDepth,
    maxLifetimeDeposits
  });
  const mailbox = mailboxService.createMailbox({
    recipientPublicKey: recipient.publicKey
  });
  const attestor = new AddressAttestor({
    now: clock,
    authorizeAddressControl: async ({ addressControlProof }) =>
      addressControlProof === 'verified-address-control-spike-proof'
  });
  const directory = new InvitationDirectory({
    now: clock,
    authorizeRegistration: async ({ directoryKey, bundle, registrationProof }) =>
      attestor.verify({
        directoryKey,
        bundle,
        attestation: registrationProof
      })
  });

  return {
    now: () => now,
    advance: (milliseconds) => {
      now += milliseconds;
    },
    recipient,
    mailbox,
    mailboxService,
    attestor,
    directory
  };
}

async function attest(state, directoryKey, bundle) {
  return state.attestor.issue({
    directoryKey,
    bundle,
    addressControlProof: 'verified-address-control-spike-proof'
  });
}

test('delivers a sealed invitation without exposing plaintext to either service', async () => {
  const state = setup();
  const directoryKey = 'github:user:789012';
  const invitation = {
    invitationId: 'invite-123',
    inviterDisplay: '@alice',
    rendezvous: 'opaque-response-mailbox',
    joinChallenge: 'challenge-456'
  };

  const registered = await state.directory.register({
    directoryKey,
    bundle: state.mailbox.bundle,
    registrationProof: await attest(state, directoryKey, state.mailbox.bundle)
  });
  assert.equal(state.directory.verifyRecord(registered), true);
  assert.equal(
    state.attestor.verify({
      directoryKey,
      bundle: registered.bundle,
      attestation: registered.addressAttestation
    }),
    true
  );

  const lookup = state.directory.lookup(directoryKey);
  const envelope = sealInvitation({
    recipientPublicKey: lookup.bundle.recipientPublicKey,
    mailboxId: lookup.bundle.mailboxId,
    invitation,
    expiresAt: state.now() + 30_000,
    now: state.now()
  });
  state.mailboxService.deposit({
    mailboxId: lookup.bundle.mailboxId,
    envelope
  });

  const directoryView = JSON.stringify(
    state.directory.inspectRecordForSpike(directoryKey)
  );
  const mailboxView = JSON.stringify(
    state.mailboxService.inspectMailboxForSpike(lookup.bundle.mailboxId)
  );
  for (const secret of Object.values(invitation)) {
    assert.equal(directoryView.includes(secret), false);
    assert.equal(mailboxView.includes(secret), false);
  }
  assert.equal(mailboxView.includes(directoryKey), false);

  const [delivery] = state.mailboxService.fetch({
    mailboxId: state.mailbox.bundle.mailboxId,
    readCapability: state.mailbox.readCapability
  });
  const opened = openInvitation({
    recipientPrivateKey: state.recipient.privateKey,
    envelope: delivery.envelope,
    expectedMailboxId: state.mailbox.bundle.mailboxId,
    now: state.now()
  });
  assert.deepEqual(opened, invitation);
});

test('rejects unauthorized reads and tampered ciphertext', () => {
  const state = setup();
  const invitation = { invitationId: 'invite-unauthorized' };
  const envelope = sealInvitation({
    recipientPublicKey: state.mailbox.bundle.recipientPublicKey,
    mailboxId: state.mailbox.bundle.mailboxId,
    invitation,
    expiresAt: state.now() + 30_000,
    now: state.now()
  });
  state.mailboxService.deposit({
    mailboxId: state.mailbox.bundle.mailboxId,
    envelope
  });

  assert.throws(
    () =>
      state.mailboxService.fetch({
        mailboxId: state.mailbox.bundle.mailboxId,
        readCapability: 'wrong-capability'
      }),
    /mailbox unavailable/
  );

  const [delivery] = state.mailboxService.fetch({
    mailboxId: state.mailbox.bundle.mailboxId,
    readCapability: state.mailbox.readCapability
  });
  const tampered = structuredClone(delivery.envelope);
  const ciphertext = Buffer.from(tampered.ciphertext, 'base64url');
  ciphertext[0] ^= 1;
  tampered.ciphertext = ciphertext.toString('base64url');

  assert.throws(() =>
    openInvitation({
      recipientPrivateKey: state.recipient.privateKey,
      envelope: tampered,
      expectedMailboxId: state.mailbox.bundle.mailboxId,
      now: state.now()
    })
  );
});

test('expires queued envelopes and the mailbox itself', () => {
  const state = setup({ mailboxTtlMs: 1_000 });
  const envelope = sealInvitation({
    recipientPublicKey: state.mailbox.bundle.recipientPublicKey,
    mailboxId: state.mailbox.bundle.mailboxId,
    invitation: { invitationId: 'short-lived' },
    expiresAt: state.now() + 400,
    now: state.now()
  });
  state.mailboxService.deposit({
    mailboxId: state.mailbox.bundle.mailboxId,
    envelope
  });

  state.advance(500);
  assert.deepEqual(
    state.mailboxService.fetch({
      mailboxId: state.mailbox.bundle.mailboxId,
      readCapability: state.mailbox.readCapability
    }),
    []
  );

  state.advance(600);
  assert.throws(
    () =>
      state.mailboxService.fetch({
        mailboxId: state.mailbox.bundle.mailboxId,
        readCapability: state.mailbox.readCapability
      }),
    /mailbox unavailable/
  );
});

test('deduplicates sender retries and does not redeliver acknowledged envelopes', () => {
  const state = setup();
  const envelope = sealInvitation({
    recipientPublicKey: state.mailbox.bundle.recipientPublicKey,
    mailboxId: state.mailbox.bundle.mailboxId,
    invitation: { invitationId: 'retry-safe' },
    expiresAt: state.now() + 30_000,
    now: state.now()
  });

  const first = state.mailboxService.deposit({
    mailboxId: state.mailbox.bundle.mailboxId,
    envelope
  });
  const retry = state.mailboxService.deposit({
    mailboxId: state.mailbox.bundle.mailboxId,
    envelope
  });
  assert.equal(retry.duplicate, true);
  assert.equal(retry.deliveryId, first.deliveryId);
  assert.equal(
    state.mailboxService.fetch({
      mailboxId: state.mailbox.bundle.mailboxId,
      readCapability: state.mailbox.readCapability
    }).length,
    1
  );

  state.mailboxService.acknowledge({
    mailboxId: state.mailbox.bundle.mailboxId,
    readCapability: state.mailbox.readCapability,
    deliveryIds: [first.deliveryId]
  });
  assert.deepEqual(
    state.mailboxService.fetch({
      mailboxId: state.mailbox.bundle.mailboxId,
      readCapability: state.mailbox.readCapability
    }),
    []
  );

  const lateReplay = state.mailboxService.deposit({
    mailboxId: state.mailbox.bundle.mailboxId,
    envelope
  });
  assert.equal(lateReplay.duplicate, true);
  assert.deepEqual(
    state.mailboxService.fetch({
      mailboxId: state.mailbox.bundle.mailboxId,
      readCapability: state.mailbox.readCapability
    }),
    []
  );
});

test('bounds queue depth and fixed-size invitation plaintext', () => {
  const state = setup({ maxQueueDepth: 1 });
  const first = sealInvitation({
    recipientPublicKey: state.mailbox.bundle.recipientPublicKey,
    mailboxId: state.mailbox.bundle.mailboxId,
    invitation: { invitationId: 'first' },
    expiresAt: state.now() + 30_000,
    now: state.now()
  });
  const second = sealInvitation({
    recipientPublicKey: state.mailbox.bundle.recipientPublicKey,
    mailboxId: state.mailbox.bundle.mailboxId,
    invitation: { invitationId: 'second' },
    expiresAt: state.now() + 30_000,
    now: state.now()
  });
  state.mailboxService.deposit({
    mailboxId: state.mailbox.bundle.mailboxId,
    envelope: first
  });
  assert.throws(
    () =>
      state.mailboxService.deposit({
        mailboxId: state.mailbox.bundle.mailboxId,
        envelope: second
      }),
    /queue limit/
  );

  assert.throws(
    () =>
      sealInvitation({
        recipientPublicKey: state.mailbox.bundle.recipientPublicKey,
        mailboxId: state.mailbox.bundle.mailboxId,
        invitation: { oversized: 'x'.repeat(2_000) },
        expiresAt: state.now() + 30_000,
        now: state.now()
      }),
    /fixed-size envelope limit/
  );
});

test('bounds total accepted deposits for the lifetime of a mailbox', () => {
  const state = setup({ maxLifetimeDeposits: 1 });
  const first = sealInvitation({
    recipientPublicKey: state.mailbox.bundle.recipientPublicKey,
    mailboxId: state.mailbox.bundle.mailboxId,
    invitation: { invitationId: 'lifetime-first' },
    expiresAt: state.now() + 30_000,
    now: state.now()
  });
  const accepted = state.mailboxService.deposit({
    mailboxId: state.mailbox.bundle.mailboxId,
    envelope: first
  });
  state.mailboxService.acknowledge({
    mailboxId: state.mailbox.bundle.mailboxId,
    readCapability: state.mailbox.readCapability,
    deliveryIds: [accepted.deliveryId]
  });

  const second = sealInvitation({
    recipientPublicKey: state.mailbox.bundle.recipientPublicKey,
    mailboxId: state.mailbox.bundle.mailboxId,
    invitation: { invitationId: 'lifetime-second' },
    expiresAt: state.now() + 30_000,
    now: state.now()
  });
  assert.throws(
    () =>
      state.mailboxService.deposit({
        mailboxId: state.mailbox.bundle.mailboxId,
        envelope: second
      }),
    /lifetime deposit limit/
  );
});

test('rejects unauthorized directory registration', async () => {
  const state = setup();
  await assert.rejects(
    state.attestor.issue({
      directoryKey: 'github:user:attacker',
      bundle: state.mailbox.bundle,
      addressControlProof: 'not-authorized'
    }),
    /address control proof rejected/
  );
  await assert.rejects(
    state.directory.register({
      directoryKey: 'github:user:attacker',
      bundle: state.mailbox.bundle,
      registrationProof: { invalid: true }
    }),
    /registration rejected/
  );
});

test('binds signed directory records to their lookup key', async () => {
  const state = setup();
  const record = await state.directory.register({
    directoryKey: 'github:user:original',
    bundle: state.mailbox.bundle,
    registrationProof: await attest(
      state,
      'github:user:original',
      state.mailbox.bundle
    )
  });
  assert.equal(state.directory.verifyRecord(record), true);

  const rebound = {
    ...record,
    directoryKey: 'github:user:substituted'
  };
  assert.equal(state.directory.verifyRecord(rebound), false);
});

test('binds address attestations independently to the address and receive bundle', async () => {
  const state = setup();
  const directoryKey = 'github:user:attested';
  const addressAttestation = await attest(
    state,
    directoryKey,
    state.mailbox.bundle
  );
  assert.equal(
    state.attestor.verify({
      directoryKey,
      bundle: state.mailbox.bundle,
      attestation: addressAttestation
    }),
    true
  );
  assert.equal(
    state.attestor.verify({
      directoryKey: 'github:user:substituted',
      bundle: state.mailbox.bundle,
      attestation: addressAttestation
    }),
    false
  );

  const otherKeys = generateReceiveKeyPair();
  const otherMailbox = state.mailboxService.createMailbox({
    recipientPublicKey: otherKeys.publicKey
  });
  assert.equal(
    state.attestor.verify({
      directoryKey,
      bundle: otherMailbox.bundle,
      attestation: addressAttestation
    }),
    false
  );
});

test('accepts a chained receive-bundle rotation and rejects rollback', async () => {
  const state = setup();
  const directoryKey = 'github:user:rotating';
  const initial = await state.directory.register({
    directoryKey,
    bundle: state.mailbox.bundle,
    registrationProof: await attest(state, directoryKey, state.mailbox.bundle)
  });

  const rotatedKeys = generateReceiveKeyPair();
  const rotatedMailbox = state.mailboxService.createMailbox({
    recipientPublicKey: rotatedKeys.publicKey,
    generation: 2,
    previousBundleDigest: bundleDigest(initial.bundle)
  });
  const rotated = await state.directory.register({
    directoryKey,
    bundle: rotatedMailbox.bundle,
    registrationProof: await attest(state, directoryKey, rotatedMailbox.bundle)
  });
  assert.equal(rotated.bundle.generation, 2);
  assert.equal(
    state.directory.lookup(directoryKey).bundle.mailboxId,
    rotatedMailbox.bundle.mailboxId
  );

  await assert.rejects(
    state.directory.register({
      directoryKey,
      bundle: initial.bundle,
      registrationProof: await attest(state, directoryKey, initial.bundle)
    }),
    /rotation chain mismatch/
  );
});
