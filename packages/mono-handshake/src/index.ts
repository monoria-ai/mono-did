import crypto from 'node:crypto';
import {
  publicKeyPemFromDidDocument,
  signPayload,
  verifyPayload,
} from '@mono/identity';
import type {
  MonoHandshakeAuditEvent,
  MonoHandshakeChallengeFrame,
  MonoHandshakeErrorCode,
  MonoHandshakeFrame,
  MonoHandshakeHelloFrame,
  MonoHandshakeResponseFrame,
  MonoHandshakeStrictVerificationResult,
  MonoLocalIdentityRecord,
} from '@mono/did-core-types';

const HANDSHAKE_PREFIX = 'mono-handshake-v1';
const DEFAULT_MAX_FRAME_AGE_MS = 2 * 60 * 1000;
const DEFAULT_MAX_CLOCK_SKEW_MS = 30 * 1000;
const DEFAULT_NONCE_CLAIM_NAMESPACE = 'mono-handshake';

export interface MonoHandshakeReplayStore {
  has(key: string, nowMs: number): boolean;
  set(key: string, expiresAtMs: number): void;
  prune(nowMs: number): void;
}

export interface MonoHandshakeGlobalNonceClaimStore {
  claim(claimKey: string, expiresAtMs: number, nowMs: number): Promise<boolean>;
}

export class InMemoryHandshakeReplayStore implements MonoHandshakeReplayStore {
  private readonly values = new Map<string, number>();

  has(key: string, nowMs: number): boolean {
    const expiresAt = this.values.get(key);
    if (expiresAt === undefined) return false;
    if (expiresAt <= nowMs) {
      this.values.delete(key);
      return false;
    }
    return true;
  }

  set(key: string, expiresAtMs: number): void {
    this.values.set(key, expiresAtMs);
  }

  prune(nowMs: number): void {
    for (const [key, expiresAt] of this.values.entries()) {
      if (expiresAt <= nowMs) {
        this.values.delete(key);
      }
    }
  }
}

export class InMemoryHandshakeGlobalNonceClaimStore implements MonoHandshakeGlobalNonceClaimStore {
  private readonly values = new Map<string, number>();

  async claim(claimKey: string, expiresAtMs: number, nowMs: number): Promise<boolean> {
    this.prune(nowMs);
    const existing = this.values.get(claimKey);
    if (existing !== undefined && existing > nowMs) {
      return false;
    }
    this.values.set(claimKey, expiresAtMs);
    return true;
  }

  private prune(nowMs: number): void {
    for (const [key, expiresAt] of this.values.entries()) {
      if (expiresAt <= nowMs) {
        this.values.delete(key);
      }
    }
  }
}

export interface MonoHandshakeVerifyOptions {
  now?: string | Date | number;
  maxFrameAgeMs?: number;
  maxClockSkewMs?: number;
  replayStore?: MonoHandshakeReplayStore;
  replayTtlMs?: number;
  globalNonceClaimStore?: MonoHandshakeGlobalNonceClaimStore;
  globalClaimNamespace?: string;
}

export function createHandshakeSessionId(): string {
  return crypto.randomUUID();
}

function buildPayload(parts: string[]): string {
  return [HANDSHAKE_PREFIX, ...parts].join('|');
}

function toNowMs(value: MonoHandshakeVerifyOptions['now']): number {
  if (value === undefined) return Date.now();
  if (typeof value === 'number') return value;
  if (value instanceof Date) return value.getTime();
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) {
    throw new Error(`Invalid verification time: ${value}`);
  }
  return parsed;
}

function parseIsoMs(value: string): number | null {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function toVerifiedAt(nowMs: number): string {
  return new Date(nowMs).toISOString();
}

function createAuditEvent(
  phase: MonoHandshakeAuditEvent['phase'],
  status: MonoHandshakeAuditEvent['status'],
  message: string,
  at: string,
  code?: MonoHandshakeErrorCode,
): MonoHandshakeAuditEvent {
  return {
    phase,
    status,
    message,
    at,
    code,
  };
}

function rejectVerification(
  phase: MonoHandshakeAuditEvent['phase'],
  code: MonoHandshakeErrorCode,
  message: string,
  verifiedAt: string,
): MonoHandshakeStrictVerificationResult {
  return {
    ok: false,
    code,
    message,
    verifiedAt,
    events: [createAuditEvent(phase, 'rejected', message, verifiedAt, code)],
  };
}

function validateSentAt(
  phase: MonoHandshakeAuditEvent['phase'],
  sentAt: string,
  nowMs: number,
  maxFrameAgeMs: number,
  maxClockSkewMs: number,
  verifiedAt: string,
): MonoHandshakeStrictVerificationResult | null {
  const sentAtMs = parseIsoMs(sentAt);
  if (sentAtMs === null) {
    return rejectVerification(phase, 'ERR_INVALID_FRAME', `Invalid ${phase} frame timestamp`, verifiedAt);
  }

  if (nowMs - sentAtMs > maxFrameAgeMs) {
    return rejectVerification(phase, 'ERR_FRAME_EXPIRED', `${phase} frame expired`, verifiedAt);
  }

  if (sentAtMs - nowMs > maxClockSkewMs) {
    return rejectVerification(phase, 'ERR_CLOCK_SKEW', `${phase} frame timestamp is too far in the future`, verifiedAt);
  }

  return null;
}

function validateExpiresAt(
  phase: MonoHandshakeAuditEvent['phase'],
  expiresAt: string,
  nowMs: number,
  maxFrameAgeMs: number,
  maxClockSkewMs: number,
  verifiedAt: string,
): MonoHandshakeStrictVerificationResult | null {
  const expiresAtMs = parseIsoMs(expiresAt);
  if (expiresAtMs === null) {
    return rejectVerification(phase, 'ERR_INVALID_FRAME', `Invalid ${phase} frame expiresAt`, verifiedAt);
  }

  if (expiresAtMs < nowMs) {
    return rejectVerification(phase, 'ERR_FRAME_EXPIRED', `${phase} frame expired (expiresAt)`, verifiedAt);
  }

  if (expiresAtMs - nowMs > maxFrameAgeMs + maxClockSkewMs) {
    return rejectVerification(phase, 'ERR_CLOCK_SKEW', `${phase} frame expiresAt window is too large`, verifiedAt);
  }

  return null;
}

function registerReplay(
  phase: MonoHandshakeAuditEvent['phase'],
  key: string,
  nowMs: number,
  verifiedAt: string,
  options: MonoHandshakeVerifyOptions,
): MonoHandshakeStrictVerificationResult | null {
  const replayStore = options.replayStore;
  if (!replayStore) return null;

  replayStore.prune(nowMs);
  if (replayStore.has(key, nowMs)) {
    return rejectVerification(phase, 'ERR_REPLAY_DETECTED', `${phase} replay detected`, verifiedAt);
  }

  const ttl = options.replayTtlMs ?? Math.max(
    options.maxFrameAgeMs ?? DEFAULT_MAX_FRAME_AGE_MS,
    options.maxClockSkewMs ?? DEFAULT_MAX_CLOCK_SKEW_MS,
  );
  replayStore.set(key, nowMs + Math.max(ttl, 1000));
  return null;
}

async function claimGlobalNonce(
  phase: MonoHandshakeAuditEvent['phase'],
  claimKey: string,
  expiresAt: string,
  nowMs: number,
  verifiedAt: string,
  options: MonoHandshakeVerifyOptions,
): Promise<MonoHandshakeStrictVerificationResult | null> {
  const store = options.globalNonceClaimStore;
  if (!store) return null;

  const expiresAtMs = parseIsoMs(expiresAt);
  if (expiresAtMs === null) {
    return rejectVerification(phase, 'ERR_INVALID_FRAME', `Invalid ${phase} frame expiresAt`, verifiedAt);
  }

  const namespace = options.globalClaimNamespace ?? DEFAULT_NONCE_CLAIM_NAMESPACE;
  const namespacedKey = `${namespace}:${claimKey}`;
  const claimed = await store.claim(namespacedKey, expiresAtMs, nowMs);
  if (!claimed) {
    return rejectVerification(phase, 'ERR_REPLAY_DETECTED', `${phase} global nonce claim rejected`, verifiedAt);
  }

  return null;
}

export function buildServerChallengePayload(input: {
  sessionId: string;
  initiatorDid: string;
  responderDid: string;
  initiatorNonce: string;
  responderNonce: string;
  expiresAt: string;
  nodeId: string;
}): string {
  return buildPayload([
    'server-challenge',
    input.sessionId,
    input.initiatorDid,
    input.responderDid,
    input.initiatorNonce,
    input.responderNonce,
    input.expiresAt,
    input.nodeId,
  ]);
}

export function buildClientResponsePayload(input: {
  sessionId: string;
  initiatorDid: string;
  responderDid: string;
  initiatorNonce: string;
  responderNonce: string;
  expiresAt: string;
  nodeId: string;
}): string {
  return buildPayload([
    'client-response',
    input.sessionId,
    input.initiatorDid,
    input.responderDid,
    input.initiatorNonce,
    input.responderNonce,
    input.expiresAt,
    input.nodeId,
  ]);
}

export function createServerChallengeFrame(input: {
  hello: MonoHandshakeHelloFrame;
  responderIdentity: MonoLocalIdentityRecord;
  responderNonce: string;
  expiresAt?: string;
  nodeId?: string;
}): MonoHandshakeChallengeFrame {
  const now = Date.now();
  const expiresAt = input.expiresAt ?? new Date(now + DEFAULT_MAX_FRAME_AGE_MS).toISOString();
  const nodeId = input.nodeId?.trim() || input.responderIdentity.did;

  const payload = buildServerChallengePayload({
    sessionId: input.hello.sessionId,
    initiatorDid: input.hello.did,
    responderDid: input.responderIdentity.did,
    initiatorNonce: input.hello.nonce,
    responderNonce: input.responderNonce,
    expiresAt,
    nodeId,
  });

  return {
    type: 'challenge',
    version: 1,
    sessionId: input.hello.sessionId,
    did: input.responderIdentity.did,
    didDocument: input.responderIdentity.document,
    nonce: input.responderNonce,
    expiresAt,
    nodeId,
    respondingToNonce: input.hello.nonce,
    signature: signPayload(input.responderIdentity.privateKeyPem, payload),
    sentAt: new Date(now).toISOString(),
  };
}

export function verifyServerChallengeFrameStrict(input: {
  hello: MonoHandshakeHelloFrame;
  challenge: MonoHandshakeChallengeFrame;
}, options: MonoHandshakeVerifyOptions = {}): MonoHandshakeStrictVerificationResult {
  const nowMs = toNowMs(options.now);
  const verifiedAt = toVerifiedAt(nowMs);
  const maxFrameAgeMs = options.maxFrameAgeMs ?? DEFAULT_MAX_FRAME_AGE_MS;
  const maxClockSkewMs = options.maxClockSkewMs ?? DEFAULT_MAX_CLOCK_SKEW_MS;

  if (input.challenge.version !== 1) {
    return rejectVerification('challenge', 'ERR_INVALID_FRAME', 'Unsupported challenge frame version', verifiedAt);
  }
  if (!input.challenge.nodeId?.trim()) {
    return rejectVerification('challenge', 'ERR_INVALID_FRAME', 'Challenge nodeId is required', verifiedAt);
  }
  if (input.hello.didDocument.id !== input.hello.did || input.challenge.didDocument.id !== input.challenge.did) {
    return rejectVerification('challenge', 'ERR_DID_MISMATCH', 'Challenge DID does not match DID document', verifiedAt);
  }
  if (input.challenge.sessionId !== input.hello.sessionId) {
    return rejectVerification('challenge', 'ERR_SESSION_MISMATCH', 'Challenge session mismatch', verifiedAt);
  }
  if (input.challenge.respondingToNonce !== input.hello.nonce) {
    return rejectVerification('challenge', 'ERR_NONCE_MISMATCH', 'Challenge nonce mismatch', verifiedAt);
  }

  const sentAtFailure = validateSentAt('challenge', input.challenge.sentAt, nowMs, maxFrameAgeMs, maxClockSkewMs, verifiedAt);
  if (sentAtFailure) {
    return sentAtFailure;
  }
  const expiresAtFailure = validateExpiresAt('challenge', input.challenge.expiresAt, nowMs, maxFrameAgeMs, maxClockSkewMs, verifiedAt);
  if (expiresAtFailure) {
    return expiresAtFailure;
  }

  const replayFailure = registerReplay(
    'challenge',
    `challenge:${input.challenge.sessionId}:${input.challenge.did}:${input.challenge.nonce}:${input.challenge.nodeId}:${input.challenge.expiresAt}:${input.challenge.signature}`,
    nowMs,
    verifiedAt,
    options,
  );
  if (replayFailure) {
    return replayFailure;
  }

  const payload = buildServerChallengePayload({
    sessionId: input.challenge.sessionId,
    initiatorDid: input.hello.did,
    responderDid: input.challenge.did,
    initiatorNonce: input.hello.nonce,
    responderNonce: input.challenge.nonce,
    expiresAt: input.challenge.expiresAt,
    nodeId: input.challenge.nodeId,
  });

  const valid = verifyPayload(
    publicKeyPemFromDidDocument(input.challenge.didDocument),
    payload,
    input.challenge.signature,
  );
  if (!valid) {
    return rejectVerification('challenge', 'ERR_SIGNATURE_INVALID', 'Challenge signature verification failed', verifiedAt);
  }

  return {
    ok: true,
    verifiedAt,
    events: [createAuditEvent('challenge', 'accepted', 'Challenge verified', verifiedAt)],
  };
}

export async function verifyServerChallengeFrameStrictWithConsensus(input: {
  hello: MonoHandshakeHelloFrame;
  challenge: MonoHandshakeChallengeFrame;
}, options: MonoHandshakeVerifyOptions = {}): Promise<MonoHandshakeStrictVerificationResult> {
  const result = verifyServerChallengeFrameStrict(input, options);
  if (!result.ok) return result;

  const nowMs = toNowMs(options.now);
  const globalFailure = await claimGlobalNonce(
    'challenge',
    `challenge:${input.challenge.sessionId}:${input.challenge.did}:${input.challenge.nonce}:${input.challenge.nodeId}:${input.challenge.signature}`,
    input.challenge.expiresAt,
    nowMs,
    result.verifiedAt,
    options,
  );
  if (globalFailure) return globalFailure;
  return result;
}

export function verifyServerChallengeFrame(input: {
  hello: MonoHandshakeHelloFrame;
  challenge: MonoHandshakeChallengeFrame;
}): boolean {
  return verifyServerChallengeFrameStrict(input).ok;
}

export function createClientResponseFrame(input: {
  hello: MonoHandshakeHelloFrame;
  challenge: MonoHandshakeChallengeFrame;
  initiatorIdentity: MonoLocalIdentityRecord;
  expiresAt?: string;
  nodeId?: string;
}): MonoHandshakeResponseFrame {
  const now = Date.now();
  const expiresAt = input.expiresAt ?? input.challenge.expiresAt;
  const nodeId = input.nodeId?.trim() || input.initiatorIdentity.did;

  const payload = buildClientResponsePayload({
    sessionId: input.challenge.sessionId,
    initiatorDid: input.initiatorIdentity.did,
    responderDid: input.challenge.did,
    initiatorNonce: input.hello.nonce,
    responderNonce: input.challenge.nonce,
    expiresAt,
    nodeId,
  });

  return {
    type: 'response',
    version: 1,
    sessionId: input.challenge.sessionId,
    did: input.initiatorIdentity.did,
    expiresAt,
    nodeId,
    respondingToNonce: input.challenge.nonce,
    signature: signPayload(input.initiatorIdentity.privateKeyPem, payload),
    sentAt: new Date(now).toISOString(),
  };
}

export function verifyClientResponseFrameStrict(input: {
  hello: MonoHandshakeHelloFrame;
  challenge: MonoHandshakeChallengeFrame;
  response: MonoHandshakeResponseFrame;
}, options: MonoHandshakeVerifyOptions = {}): MonoHandshakeStrictVerificationResult {
  const nowMs = toNowMs(options.now);
  const verifiedAt = toVerifiedAt(nowMs);
  const maxFrameAgeMs = options.maxFrameAgeMs ?? DEFAULT_MAX_FRAME_AGE_MS;
  const maxClockSkewMs = options.maxClockSkewMs ?? DEFAULT_MAX_CLOCK_SKEW_MS;

  if (input.response.version !== 1) {
    return rejectVerification('response', 'ERR_INVALID_FRAME', 'Unsupported response frame version', verifiedAt);
  }
  if (!input.response.nodeId?.trim()) {
    return rejectVerification('response', 'ERR_INVALID_FRAME', 'Response nodeId is required', verifiedAt);
  }
  if (input.hello.didDocument.id !== input.hello.did || input.challenge.didDocument.id !== input.challenge.did) {
    return rejectVerification('response', 'ERR_DID_MISMATCH', 'Response verification DID mismatch', verifiedAt);
  }
  if (input.response.sessionId !== input.challenge.sessionId || input.response.sessionId !== input.hello.sessionId) {
    return rejectVerification('response', 'ERR_SESSION_MISMATCH', 'Response session mismatch', verifiedAt);
  }
  if (input.response.respondingToNonce !== input.challenge.nonce) {
    return rejectVerification('response', 'ERR_NONCE_MISMATCH', 'Response nonce mismatch', verifiedAt);
  }
  if (input.response.did !== input.hello.did) {
    return rejectVerification('response', 'ERR_DID_MISMATCH', 'Response DID mismatch', verifiedAt);
  }

  const sentAtFailure = validateSentAt('response', input.response.sentAt, nowMs, maxFrameAgeMs, maxClockSkewMs, verifiedAt);
  if (sentAtFailure) {
    return sentAtFailure;
  }
  const expiresAtFailure = validateExpiresAt('response', input.response.expiresAt, nowMs, maxFrameAgeMs, maxClockSkewMs, verifiedAt);
  if (expiresAtFailure) {
    return expiresAtFailure;
  }

  const replayFailure = registerReplay(
    'response',
    `response:${input.response.sessionId}:${input.response.did}:${input.response.respondingToNonce}:${input.response.nodeId}:${input.response.expiresAt}:${input.response.signature}`,
    nowMs,
    verifiedAt,
    options,
  );
  if (replayFailure) {
    return replayFailure;
  }

  const payload = buildClientResponsePayload({
    sessionId: input.response.sessionId,
    initiatorDid: input.hello.did,
    responderDid: input.challenge.did,
    initiatorNonce: input.hello.nonce,
    responderNonce: input.challenge.nonce,
    expiresAt: input.response.expiresAt,
    nodeId: input.response.nodeId,
  });

  const valid = verifyPayload(
    publicKeyPemFromDidDocument(input.hello.didDocument),
    payload,
    input.response.signature,
  );
  if (!valid) {
    return rejectVerification('response', 'ERR_SIGNATURE_INVALID', 'Response signature verification failed', verifiedAt);
  }

  return {
    ok: true,
    verifiedAt,
    events: [createAuditEvent('response', 'accepted', 'Response verified', verifiedAt)],
  };
}

export async function verifyClientResponseFrameStrictWithConsensus(input: {
  hello: MonoHandshakeHelloFrame;
  challenge: MonoHandshakeChallengeFrame;
  response: MonoHandshakeResponseFrame;
}, options: MonoHandshakeVerifyOptions = {}): Promise<MonoHandshakeStrictVerificationResult> {
  const result = verifyClientResponseFrameStrict(input, options);
  if (!result.ok) return result;

  const nowMs = toNowMs(options.now);
  const globalFailure = await claimGlobalNonce(
    'response',
    `response:${input.response.sessionId}:${input.response.did}:${input.response.respondingToNonce}:${input.response.nodeId}:${input.response.signature}`,
    input.response.expiresAt,
    nowMs,
    result.verifiedAt,
    options,
  );
  if (globalFailure) return globalFailure;
  return result;
}

export function verifyClientResponseFrame(input: {
  hello: MonoHandshakeHelloFrame;
  challenge: MonoHandshakeChallengeFrame;
  response: MonoHandshakeResponseFrame;
}): boolean {
  return verifyClientResponseFrameStrict(input).ok;
}

export function assertHandshakeFrameType<T extends MonoHandshakeFrame['type']>(
  frame: { type: string },
  type: T,
): asserts frame is Extract<MonoHandshakeFrame, { type: T }> {
  if (frame.type !== type) {
    throw new Error(`Expected handshake frame ${type}, received ${frame.type}`);
  }
}
