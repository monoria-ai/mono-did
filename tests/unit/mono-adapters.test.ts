import { describe, expect, it } from 'vitest';
import { createDefaultMonoAdapters } from '@mono/adapters';

describe('mono adapters', () => {
  it('provides stable identity/handshake/protocol adapters with interoperable defaults', async () => {
    const adapters = createDefaultMonoAdapters();

    const initiator = await adapters.identity.createIdentity();
    const responder = await adapters.identity.createIdentity();

    const hello = {
      type: 'hello' as const,
      version: 1 as const,
      sessionId: adapters.handshake.createSessionId(),
      did: initiator.did,
      didDocument: initiator.document,
      nonce: adapters.identity.createNonce(),
      sentAt: new Date().toISOString(),
    };

    const challenge = adapters.handshake.createServerChallenge({
      hello,
      responderIdentity: responder,
      responderNonce: adapters.identity.createNonce(),
    });
    expect(adapters.handshake.verifyServerChallenge({ hello, challenge })).toBe(true);

    const response = adapters.handshake.createClientResponse({
      hello,
      challenge,
      initiatorIdentity: initiator,
    });
    expect(adapters.handshake.verifyClientResponse({ hello, challenge, response })).toBe(true);

    const encoded = adapters.protocol.encodeFrame(challenge);
    const decoded = adapters.protocol.decodeFrame<typeof challenge>(encoded.trim());
    expect(decoded.type).toBe('challenge');
    expect(adapters.protocol.handshakeProtocol).toBe('/mono/handshake/1.0.0');

    const lifecycle = adapters.identity.createLifecycleRecord(initiator);
    const rotated = await adapters.identity.rotateLifecycleRecord(lifecycle, { reason: 'policy' });
    const revoked = adapters.identity.revokeLifecycleRecord(rotated, { reason: 'cleanup' });
    expect(revoked.current).toBeNull();

    const strict = adapters.handshake.verifyServerChallengeStrict({ hello, challenge }, { now: new Date().toISOString() });
    expect(strict.ok).toBe(true);
  });
});
