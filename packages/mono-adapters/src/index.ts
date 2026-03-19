import {
  createIdentityLifecycleRecord,
  createDidPeerIdentity,
  createMultikeyFromPublicKeyPem,
  createNonce,
  publicIdentityFromRecord,
  publicKeyPemFromDidDocument,
  publicKeyPemFromMultikey,
  revokeIdentityLifecycleRecord,
  resolveDidPeer2,
  rotateIdentityLifecycleRecord,
  signPayload,
  verifyPayload,
} from '@mono/identity';
import {
  InMemoryHandshakeReplayStore,
  type MonoHandshakeReplayStore,
  type MonoHandshakeVerifyOptions,
  assertHandshakeFrameType,
  createClientResponseFrame,
  createHandshakeSessionId,
  createServerChallengeFrame,
  verifyClientResponseFrameStrict,
  verifyServerChallengeFrameStrict,
  verifyClientResponseFrame,
  verifyServerChallengeFrame,
} from '@mono/handshake';
import {
  MONO_HANDSHAKE_PROTOCOL,
  MONO_JSON_LINE_DELIMITER,
  decodeFrame,
  encodeFrame,
} from '@mono/protocol';
import type {
  MonoDidDocument,
  MonoHandshakeChallengeFrame,
  MonoHandshakeFrame,
  MonoHandshakeHelloFrame,
  MonoHandshakeResponseFrame,
  MonoHandshakeStrictVerificationResult,
  MonoIdentityLifecycleRecord,
  MonoLocalIdentityRecord,
  MonoPublicIdentity,
} from '@mono/did-core-types';

export interface IdentityAdapter {
  createIdentity(): Promise<MonoLocalIdentityRecord>;
  createLifecycleRecord(record: MonoLocalIdentityRecord): MonoIdentityLifecycleRecord;
  rotateLifecycleRecord(
    lifecycle: MonoIdentityLifecycleRecord,
    options?: { reason?: string; rotateAt?: string },
  ): Promise<MonoIdentityLifecycleRecord>;
  revokeLifecycleRecord(
    lifecycle: MonoIdentityLifecycleRecord,
    options?: { reason?: string; revokeAt?: string },
  ): MonoIdentityLifecycleRecord;
  resolveDid(did: string): MonoDidDocument;
  toPublicIdentity(record: MonoLocalIdentityRecord): MonoPublicIdentity;
  createNonce(bytes?: number): string;
  sign(privateKeyPem: string, payload: string): string;
  verify(publicKeyPem: string, payload: string, signature: string): boolean;
  multikeyFromPublicKeyPem(publicKeyPem: string): string;
  publicKeyPemFromMultikey(multikey: string): string;
  publicKeyPemFromDidDocument(document: MonoDidDocument): string;
}

export interface HandshakeAdapter {
  createSessionId(): string;
  createReplayStore(): MonoHandshakeReplayStore;
  createServerChallenge(input: {
    hello: MonoHandshakeHelloFrame;
    responderIdentity: MonoLocalIdentityRecord;
    responderNonce: string;
  }): MonoHandshakeChallengeFrame;
  verifyServerChallenge(input: {
    hello: MonoHandshakeHelloFrame;
    challenge: MonoHandshakeChallengeFrame;
  }): boolean;
  verifyServerChallengeStrict(input: {
    hello: MonoHandshakeHelloFrame;
    challenge: MonoHandshakeChallengeFrame;
  }, options?: MonoHandshakeVerifyOptions): MonoHandshakeStrictVerificationResult;
  createClientResponse(input: {
    hello: MonoHandshakeHelloFrame;
    challenge: MonoHandshakeChallengeFrame;
    initiatorIdentity: MonoLocalIdentityRecord;
  }): MonoHandshakeResponseFrame;
  verifyClientResponse(input: {
    hello: MonoHandshakeHelloFrame;
    challenge: MonoHandshakeChallengeFrame;
    response: MonoHandshakeResponseFrame;
  }): boolean;
  verifyClientResponseStrict(input: {
    hello: MonoHandshakeHelloFrame;
    challenge: MonoHandshakeChallengeFrame;
    response: MonoHandshakeResponseFrame;
  }, options?: MonoHandshakeVerifyOptions): MonoHandshakeStrictVerificationResult;
  assertFrameType<T extends MonoHandshakeFrame['type']>(
    frame: { type: string },
    type: T,
  ): asserts frame is Extract<MonoHandshakeFrame, { type: T }>;
}

export interface ProtocolAdapter {
  readonly handshakeProtocol: string;
  readonly jsonLineDelimiter: string;
  encodeFrame<T>(frame: T): string;
  decodeFrame<T>(line: string): T;
}

export interface MonoDidAdapters {
  identity: IdentityAdapter;
  handshake: HandshakeAdapter;
  protocol: ProtocolAdapter;
}

export function createDefaultMonoAdapters(): MonoDidAdapters {
  return {
    identity: {
      createIdentity: createDidPeerIdentity,
      createLifecycleRecord: createIdentityLifecycleRecord,
      rotateLifecycleRecord: rotateIdentityLifecycleRecord,
      revokeLifecycleRecord: revokeIdentityLifecycleRecord,
      resolveDid: resolveDidPeer2,
      toPublicIdentity: publicIdentityFromRecord,
      createNonce,
      sign: signPayload,
      verify: verifyPayload,
      multikeyFromPublicKeyPem: createMultikeyFromPublicKeyPem,
      publicKeyPemFromMultikey,
      publicKeyPemFromDidDocument,
    },
    handshake: {
      createSessionId: createHandshakeSessionId,
      createReplayStore: () => new InMemoryHandshakeReplayStore(),
      createServerChallenge: createServerChallengeFrame,
      verifyServerChallenge: verifyServerChallengeFrame,
      verifyServerChallengeStrict: verifyServerChallengeFrameStrict,
      createClientResponse: createClientResponseFrame,
      verifyClientResponse: verifyClientResponseFrame,
      verifyClientResponseStrict: verifyClientResponseFrameStrict,
      assertFrameType: assertHandshakeFrameType,
    },
    protocol: {
      handshakeProtocol: MONO_HANDSHAKE_PROTOCOL,
      jsonLineDelimiter: MONO_JSON_LINE_DELIMITER,
      encodeFrame,
      decodeFrame,
    },
  };
}

export const defaultMonoAdapters = createDefaultMonoAdapters();
