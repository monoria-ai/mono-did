import { describe, expect, it } from 'vitest';
import {
  createDefaultMonoAdapters,
  createDidPeerIdentity,
  createHandshakeSessionId,
  createDidKeyEventLog,
  verifyDidKeyEventLog,
  MONO_HANDSHAKE_PROTOCOL,
} from '@mono/did';

describe('@mono/did aggregate package', () => {
  it('re-exports adapter, identity, handshake and protocol APIs from one entry', async () => {
    const adapters = createDefaultMonoAdapters();
    const identity = await createDidPeerIdentity();

    const log = createDidKeyEventLog(identity, { nodeId: 'node-test' });
    const verification = verifyDidKeyEventLog(log);

    expect(verification.ok).toBe(true);
    expect(typeof createHandshakeSessionId()).toBe('string');
    expect(adapters.protocol.handshakeProtocol).toBe(MONO_HANDSHAKE_PROTOCOL);
  });
});
