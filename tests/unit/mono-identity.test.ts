import { describe, expect, it } from 'vitest';
import {
  createDidPeerIdentity,
  createIdentityLifecycleRecord,
  publicIdentityFromRecord,
  revokeIdentityLifecycleRecord,
  rotateIdentityLifecycleRecord,
  resolveDidPeer2,
  signPayload,
  verifyPayload,
} from '@mono/identity';

describe('mono identity', () => {
  it('creates a did:peer:2 identity that resolves back into the same document', async () => {
    const identity = await createDidPeerIdentity();

    expect(identity.did.startsWith('did:peer:2.')).toBe(true);
    expect(resolveDidPeer2(identity.did)).toEqual(identity.document);
  });

  it('signs and verifies payloads with the generated authentication key', async () => {
    const identity = await createDidPeerIdentity();
    const publicIdentity = publicIdentityFromRecord(identity);
    const payload = `mono:${publicIdentity.did}`;
    const signature = signPayload(identity.privateKeyPem, payload);

    expect(verifyPayload(identity.publicKeyPem, payload, signature)).toBe(true);
    expect(verifyPayload(identity.publicKeyPem, `${payload}:tampered`, signature)).toBe(false);
  });

  it('rotates and revokes identity lifecycle records', async () => {
    const initial = await createDidPeerIdentity();
    const lifecycle = createIdentityLifecycleRecord(initial);

    const rotated = await rotateIdentityLifecycleRecord(lifecycle, { reason: 'scheduled' });
    if (!rotated.current) {
      throw new Error('Expected rotated identity to be active');
    }
    expect(rotated.current.did).not.toBe(initial.did);
    expect(rotated.history.length).toBe(1);
    expect(rotated.history[0]?.reason).toBe('scheduled');
    expect(rotated.history[0]?.status).toBe('rotated');

    const revoked = revokeIdentityLifecycleRecord(rotated, { reason: 'decommissioned' });
    expect(revoked.current).toBeNull();
    expect(revoked.history.length).toBe(2);
    expect(revoked.history[1]?.reason).toBe('decommissioned');
    expect(revoked.history[1]?.status).toBe('revoked');
  });
});
