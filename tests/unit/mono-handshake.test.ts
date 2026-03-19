import { describe, expect, it } from 'vitest';
import { createDidPeerIdentity, createNonce } from '@mono/identity';
import {
  InMemoryHandshakeReplayStore,
  createClientResponseFrame,
  createHandshakeSessionId,
  createServerChallengeFrame,
  verifyClientResponseFrameStrict,
  verifyServerChallengeFrameStrict,
  verifyClientResponseFrame,
  verifyServerChallengeFrame,
} from '@mono/handshake';

describe('mono handshake', () => {
  it('completes a mutual challenge-response round trip', async () => {
    const initiator = await createDidPeerIdentity();
    const responder = await createDidPeerIdentity();

    const hello = {
      type: 'hello' as const,
      version: 1 as const,
      sessionId: createHandshakeSessionId(),
      did: initiator.did,
      didDocument: initiator.document,
      nonce: createNonce(),
      sentAt: new Date().toISOString(),
    };

    const challenge = createServerChallengeFrame({
      hello,
      responderIdentity: responder,
      responderNonce: createNonce(),
    });

    expect(verifyServerChallengeFrame({ hello, challenge })).toBe(true);

    const response = createClientResponseFrame({
      hello,
      challenge,
      initiatorIdentity: initiator,
    });

    expect(verifyClientResponseFrame({ hello, challenge, response })).toBe(true);
  });

  it('rejects replayed challenge frames in strict mode', async () => {
    const initiator = await createDidPeerIdentity();
    const responder = await createDidPeerIdentity();
    const replayStore = new InMemoryHandshakeReplayStore();
    const nowIso = new Date().toISOString();

    const hello = {
      type: 'hello' as const,
      version: 1 as const,
      sessionId: createHandshakeSessionId(),
      did: initiator.did,
      didDocument: initiator.document,
      nonce: createNonce(),
      sentAt: nowIso,
    };
    const challenge = createServerChallengeFrame({
      hello,
      responderIdentity: responder,
      responderNonce: createNonce(),
    });

    const first = verifyServerChallengeFrameStrict({ hello, challenge }, {
      now: nowIso,
      replayStore,
    });
    expect(first.ok).toBe(true);

    const second = verifyServerChallengeFrameStrict({ hello, challenge }, {
      now: nowIso,
      replayStore,
    });
    expect(second.ok).toBe(false);
    if (!second.ok) {
      expect(second.code).toBe('ERR_REPLAY_DETECTED');
    }
  });

  it('rejects stale response frames in strict mode', async () => {
    const initiator = await createDidPeerIdentity();
    const responder = await createDidPeerIdentity();
    const now = Date.now();
    const nowIso = new Date(now).toISOString();

    const hello = {
      type: 'hello' as const,
      version: 1 as const,
      sessionId: createHandshakeSessionId(),
      did: initiator.did,
      didDocument: initiator.document,
      nonce: createNonce(),
      sentAt: nowIso,
    };
    const challenge = createServerChallengeFrame({
      hello,
      responderIdentity: responder,
      responderNonce: createNonce(),
    });
    const response = createClientResponseFrame({
      hello,
      challenge,
      initiatorIdentity: initiator,
    });

    const staleNow = new Date(now + 10 * 60 * 1000).toISOString();
    const result = verifyClientResponseFrameStrict({ hello, challenge, response }, {
      now: staleNow,
      maxFrameAgeMs: 60 * 1000,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe('ERR_FRAME_EXPIRED');
    }
  });
});
