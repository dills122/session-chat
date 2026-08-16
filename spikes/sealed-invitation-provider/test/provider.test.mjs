import assert from 'node:assert/strict';
import test from 'node:test';
import { AddressAttestor } from '../src/attestor.mjs';
import { generateReceiveKeyPair, openInvitation, sealInvitation } from '../src/crypto.mjs';
import { bundleDigest, InvitationDirectory, InvitationMailboxService } from '../src/provider.mjs';

function setup({ maxQueueDepth = 16, maxLifetimeDeposits = 64, mailboxTtlMs = 60_000 } = {}) {
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

  const directoryView = JSON.stringify(state.directory.inspectRecordForSpike(directoryKey));
  const mailboxView = JSON.stringify(state.mailboxService.inspectMailboxForSpike(lookup.bundle.mailboxId));
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
  assert.throws(
    () =>
      state.mailboxService.fetch({
        mailboxId: state.mailbox.bundle.mailboxId,
        readCapability: state.mailbox.acknowledgementCapability
      }),
    /mailbox unavailable/
  );

  const [delivery] = state.mailboxService.fetch({
    mailboxId: state.mailbox.bundle.mailboxId,
    readCapability: state.mailbox.readCapability
  });
  assert.throws(
    () =>
      state.mailboxService.acknowledge({
        mailboxId: state.mailbox.bundle.mailboxId,
        acknowledgementCapability: state.mailbox.readCapability,
        deliveryIds: [delivery.deliveryId]
      }),
    /mailbox unavailable/
  );
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
    acknowledgementCapability: state.mailbox.acknowledgementCapability,
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
    acknowledgementCapability: state.mailbox.acknowledgementCapability,
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
    registrationProof: await attest(state, 'github:user:original', state.mailbox.bundle)
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
  const addressAttestation = await attest(state, directoryKey, state.mailbox.bundle);
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
  assert.equal(state.directory.lookup(directoryKey).bundle.mailboxId, rotatedMailbox.bundle.mailboxId);

  await assert.rejects(
    state.directory.register({
      directoryKey,
      bundle: initial.bundle,
      registrationProof: await attest(state, directoryKey, initial.bundle)
    }),
    /rotation chain mismatch/
  );
});

test('allows only one concurrent successor for the same bundle generation', async () => {
  const state = setup();
  const directoryKey = 'github:user:competing-rotation';
  let authorizeSuccessor;
  const bothSuccessorsWaiting = new Promise((resolve) => {
    authorizeSuccessor = resolve;
  });
  let waitingSuccessors = 0;
  const directory = new InvitationDirectory({
    now: state.now,
    authorizeRegistration: async ({ bundle }) => {
      if (bundle.generation === 1) {
        return true;
      }
      waitingSuccessors += 1;
      if (waitingSuccessors === 2) {
        authorizeSuccessor();
      }
      await bothSuccessorsWaiting;
      return true;
    }
  });
  const initial = await directory.register({
    directoryKey,
    bundle: state.mailbox.bundle,
    registrationProof: { fixture: 'initial' }
  });
  const previousBundleDigest = bundleDigest(initial.bundle);

  const firstKeys = generateReceiveKeyPair();
  const firstMailbox = state.mailboxService.createMailbox({
    recipientPublicKey: firstKeys.publicKey,
    generation: 2,
    previousBundleDigest
  });
  const secondKeys = generateReceiveKeyPair();
  const secondMailbox = state.mailboxService.createMailbox({
    recipientPublicKey: secondKeys.publicKey,
    generation: 2,
    previousBundleDigest
  });

  const attempts = await Promise.allSettled([
    directory.register({
      directoryKey,
      bundle: firstMailbox.bundle,
      registrationProof: { fixture: 'first-successor' }
    }),
    directory.register({
      directoryKey,
      bundle: secondMailbox.bundle,
      registrationProof: { fixture: 'second-successor' }
    })
  ]);

  assert.equal(attempts.filter(({ status }) => status === 'fulfilled').length, 1);
  assert.equal(attempts.filter(({ status }) => status === 'rejected').length, 1);
  assert.match(attempts.find(({ status }) => status === 'rejected').reason.message, /rotation chain mismatch/);

  const winner = attempts.find(({ status }) => status === 'fulfilled').value;
  assert.equal(directory.lookup(directoryKey).bundle.mailboxId, winner.bundle.mailboxId);
});

test('snapshots directory registration inputs before asynchronous authorization', async () => {
  const state = setup();
  const directoryKey = 'github:user:mutable-registration';
  const originalBundle = structuredClone(state.mailbox.bundle);
  let authorizationStarted;
  let finishAuthorization;
  const started = new Promise((resolve) => {
    authorizationStarted = resolve;
  });
  const authorized = new Promise((resolve) => {
    finishAuthorization = resolve;
  });
  const directory = new InvitationDirectory({
    now: state.now,
    authorizeRegistration: async ({ bundle, registrationProof }) => {
      assert.deepEqual(bundle, originalBundle);
      assert.deepEqual(registrationProof, { fixture: 'bounded-proof' });
      authorizationStarted();
      await authorized;
      assert.deepEqual(bundle, originalBundle);
      assert.deepEqual(registrationProof, { fixture: 'bounded-proof' });
      return true;
    }
  });
  const mutableBundle = structuredClone(originalBundle);
  const mutableProof = { fixture: 'bounded-proof' };
  const pending = directory.register({
    directoryKey,
    bundle: mutableBundle,
    registrationProof: mutableProof
  });

  await started;
  mutableBundle.recipientPublicKey = generateReceiveKeyPair().publicKey;
  mutableProof.fixture = 'mutated-after-authorization-started';
  finishAuthorization();

  const registered = await pending;
  assert.deepEqual(registered.bundle, originalBundle);
  assert.deepEqual(registered.addressAttestation, { fixture: 'bounded-proof' });
});

test('bounds registration proof structure before authorization', async () => {
  const state = setup();
  let authorizationCalls = 0;
  const directory = new InvitationDirectory({
    now: state.now,
    authorizeRegistration: async () => {
      authorizationCalls += 1;
      return true;
    }
  });

  await assert.rejects(
    directory.register({
      directoryKey: 'github:user:oversized-proof',
      bundle: state.mailbox.bundle,
      registrationProof: { proof: 'x'.repeat(9_000) }
    }),
    /invalid directory registration/
  );
  await assert.rejects(
    directory.register({
      directoryKey: 'github:user:deep-proof',
      bundle: state.mailbox.bundle,
      registrationProof: { one: { two: { three: { four: { five: true } } } } }
    }),
    /invalid directory registration/
  );
  await assert.rejects(
    directory.register({
      directoryKey: 'github:user:wrong-proof-type',
      bundle: state.mailbox.bundle,
      registrationProof: 'not-an-object'
    }),
    /invalid directory registration/
  );
  await assert.rejects(
    directory.register({
      directoryKey: 'github:user:too-many-proof-fields',
      bundle: state.mailbox.bundle,
      registrationProof: Object.fromEntries(
        Array.from({ length: 33 }, (_, index) => [`field${index}`, index])
      )
    }),
    /invalid directory registration/
  );
  assert.equal(authorizationCalls, 0);
});

test('rechecks bundle freshness after asynchronous registration authorization', async () => {
  const state = setup();
  const directoryKey = 'github:user:expiring-registration';
  let authorizationStarted;
  let finishAuthorization;
  const started = new Promise((resolve) => {
    authorizationStarted = resolve;
  });
  const authorized = new Promise((resolve) => {
    finishAuthorization = resolve;
  });
  const directory = new InvitationDirectory({
    now: state.now,
    authorizeRegistration: async () => {
      authorizationStarted();
      await authorized;
      return true;
    }
  });
  const pending = directory.register({
    directoryKey,
    bundle: state.mailbox.bundle,
    registrationProof: { fixture: 'expires-during-authorization' }
  });

  await started;
  state.advance(60_000);
  finishAuthorization();

  await assert.rejects(pending, /invalid directory registration/);
  assert.equal(directory.inspectRecordForSpike(directoryKey), undefined);
});

test('bounds acknowledgement identifiers before allocating work', () => {
  const state = setup({ maxQueueDepth: 2 });
  const request = {
    mailboxId: state.mailbox.bundle.mailboxId,
    acknowledgementCapability: state.mailbox.acknowledgementCapability
  };

  assert.throws(
    () => state.mailboxService.acknowledge({ ...request, deliveryIds: 'not-an-array' }),
    /invalid acknowledgement request/
  );
  assert.throws(
    () => state.mailboxService.acknowledge({ ...request, deliveryIds: ['not-a-delivery-id'] }),
    /invalid acknowledgement request/
  );
  assert.throws(
    () =>
      state.mailboxService.acknowledge({
        ...request,
        deliveryIds: [
          Buffer.alloc(16, 1).toString('base64url'),
          Buffer.alloc(16, 2).toString('base64url'),
          Buffer.alloc(16, 3).toString('base64url')
        ]
      }),
    /invalid acknowledgement request/
  );
});

test('snapshots attestation inputs before asynchronous address authorization', async () => {
  const state = setup();
  const directoryKey = 'github:user:mutable-attestation';
  const originalBundle = structuredClone(state.mailbox.bundle);
  let authorizationStarted;
  let finishAuthorization;
  const started = new Promise((resolve) => {
    authorizationStarted = resolve;
  });
  const authorized = new Promise((resolve) => {
    finishAuthorization = resolve;
  });
  const attestor = new AddressAttestor({
    now: state.now,
    authorizeAddressControl: async ({ bundle }) => {
      assert.deepEqual(bundle, originalBundle);
      authorizationStarted();
      await authorized;
      assert.deepEqual(bundle, originalBundle);
      return true;
    }
  });
  const mutableBundle = structuredClone(originalBundle);
  const pending = attestor.issue({
    directoryKey,
    bundle: mutableBundle,
    addressControlProof: 'bounded-proof'
  });

  await started;
  mutableBundle.recipientPublicKey = generateReceiveKeyPair().publicKey;
  finishAuthorization();

  const attestation = await pending;
  assert.equal(attestor.verify({ directoryKey, bundle: originalBundle, attestation }), true);
});

test('bounds address-control proof before authorization', async () => {
  const state = setup();
  let authorizationCalls = 0;
  const attestor = new AddressAttestor({
    now: state.now,
    authorizeAddressControl: async () => {
      authorizationCalls += 1;
      return true;
    }
  });

  await assert.rejects(
    attestor.issue({
      directoryKey: 'github:user:oversized-address-proof',
      bundle: state.mailbox.bundle,
      addressControlProof: 'x'.repeat(4_097)
    }),
    /invalid address attestation request/
  );
  assert.equal(authorizationCalls, 0);
});

test('rejects unknown, oversized, deep, cyclic, accessor-backed, and symbol-keyed receive-bundle properties before authorization', async () => {
  const state = setup();
  let directoryAuthorizationCalls = 0;
  let attestorAuthorizationCalls = 0;
  let bundleGetterCalls = 0;
  const directory = new InvitationDirectory({
    now: state.now,
    authorizeRegistration: async () => {
      directoryAuthorizationCalls += 1;
      return true;
    }
  });
  const attestor = new AddressAttestor({
    now: state.now,
    authorizeAddressControl: async () => {
      attestorAuthorizationCalls += 1;
      return true;
    }
  });
  const invalidBundles = [
    { ...state.mailbox.bundle, transportProfile: 'Private' },
    { ...state.mailbox.bundle, extra: 'x'.repeat(1_000_000) },
    { ...state.mailbox.bundle, extra: { one: { two: { three: { four: true } } } } }
  ];
  const cyclic = { ...state.mailbox.bundle };
  cyclic.extra = cyclic;
  invalidBundles.push(cyclic);
  const accessorExtra = { ...state.mailbox.bundle };
  Object.defineProperty(accessorExtra, 'extra', {
    enumerable: true,
    get() {
      bundleGetterCalls += 1;
      return 'must-not-be-read';
    }
  });
  invalidBundles.push(accessorExtra);
  const accessorField = { ...state.mailbox.bundle };
  Object.defineProperty(accessorField, 'expiresAt', {
    enumerable: true,
    get() {
      bundleGetterCalls += 1;
      return state.mailbox.bundle.expiresAt;
    }
  });
  invalidBundles.push(accessorField);
  const symbolExtra = { ...state.mailbox.bundle };
  symbolExtra[Symbol('extra')] = 'must-be-rejected';
  invalidBundles.push(symbolExtra);

  for (const [index, bundle] of invalidBundles.entries()) {
    await assert.rejects(
      directory.register({
        directoryKey: `github:user:invalid-bundle-${index}`,
        bundle,
        registrationProof: { fixture: 'bounded-proof' }
      }),
      /invalid directory registration/
    );
    await assert.rejects(
      attestor.issue({
        directoryKey: `github:user:invalid-bundle-${index}`,
        bundle,
        addressControlProof: 'bounded-proof'
      }),
      /invalid address attestation request/
    );
  }
  assert.equal(bundleGetterCalls, 0);
  assert.equal(directoryAuthorizationCalls, 0);
  assert.equal(attestorAuthorizationCalls, 0);
});

test('authenticates exactly the closed receive-bundle schema', async () => {
  const state = setup();
  const directoryKey = 'github:user:closed-bundle';
  const attestation = await attest(state, directoryKey, state.mailbox.bundle);
  const record = await state.directory.register({
    directoryKey,
    bundle: state.mailbox.bundle,
    registrationProof: attestation
  });
  const mutations = [
    { version: 2 },
    { generation: 2 },
    { previousBundleDigest: Buffer.alloc(32, 1).toString('base64url') },
    { mailboxId: Buffer.alloc(32, 2).toString('base64url') },
    { recipientPublicKey: generateReceiveKeyPair().publicKey },
    { expiresAt: record.bundle.expiresAt + 1 },
    { transportProfile: 'Private' }
  ];

  for (const mutation of mutations) {
    const changed = { ...record, bundle: { ...record.bundle, ...mutation } };
    assert.equal(state.directory.verifyRecord(changed), false);
    assert.equal(
      state.attestor.verify({
        directoryKey,
        bundle: changed.bundle,
        attestation: record.addressAttestation
      }),
      false
    );
  }
});
