export interface MonoVerificationMethod {
  id: string;
  type: 'Multikey';
  controller: string;
  publicKeyMultibase: string;
}

export interface MonoServiceEndpoint {
  uri?: string;
  routing?: string[];
  accepts?: string[];
}

export interface MonoService {
  id: string;
  type: string;
  serviceEndpoint: string | MonoServiceEndpoint;
}

export interface MonoDidDocument {
  id: string;
  verificationMethod: MonoVerificationMethod[];
  authentication: string[];
  service?: MonoService[];
}

export interface MonoLocalIdentityRecord {
  did: string;
  document: MonoDidDocument;
  authKeyId: string;
  publicKeyMultibase: string;
  privateKeyPem: string;
  publicKeyPem: string;
  createdAt: string;
  updatedAt: string;
}

export interface MonoPublicIdentity {
  did: string;
  document: MonoDidDocument;
  authKeyId: string;
  publicKeyMultibase: string;
  createdAt: string;
  updatedAt: string;
}

export type MonoIdentityLifecycleStatus = 'rotated' | 'revoked';

export interface MonoIdentityLifecycleEntry {
  did: string;
  authKeyId: string;
  publicKeyMultibase: string;
  status: MonoIdentityLifecycleStatus;
  changedAt: string;
  reason?: string;
}

export interface MonoIdentityLifecycleRecord {
  current: MonoLocalIdentityRecord | null;
  history: MonoIdentityLifecycleEntry[];
  createdAt: string;
  updatedAt: string;
}

export type MonoDidKeyEventType = 'create' | 'rotate' | 'revoke';

export interface MonoDidKeyEvent {
  did: string;
  version: number;
  prevHash: string | null;
  type: MonoDidKeyEventType;
  signerPublicKeyMultibase: string;
  publicKeyMultibase?: string;
  keyId?: string;
  nodeId: string;
  createdAt: string;
  reason?: string;
  signature: string;
}

export interface MonoDidKeyEventLog {
  did: string;
  events: MonoDidKeyEvent[];
  updatedAt: string;
  anchorHash?: string;
}

export type MonoDidKeyEventLogErrorCode =
  | 'ERR_EMPTY_LOG'
  | 'ERR_DID_MISMATCH'
  | 'ERR_INVALID_VERSION'
  | 'ERR_PREV_HASH_MISMATCH'
  | 'ERR_MISSING_KEY'
  | 'ERR_SIGNER_MISMATCH'
  | 'ERR_SIGNATURE_INVALID'
  | 'ERR_EVENT_AFTER_REVOKE';

export type MonoDidKeyEventLogVerificationResult =
  | {
      ok: true;
      activePublicKeyMultibase: string | null;
      revoked: boolean;
      headHash: string;
    }
  | {
      ok: false;
      code: MonoDidKeyEventLogErrorCode;
      message: string;
      eventIndex: number;
    };

export interface MonoHandshakeHelloFrame {
  type: 'hello';
  version: 1;
  sessionId: string;
  did: string;
  didDocument: MonoDidDocument;
  nonce: string;
  sentAt: string;
}

export interface MonoHandshakeChallengeFrame {
  type: 'challenge';
  version: 1;
  sessionId: string;
  did: string;
  didDocument: MonoDidDocument;
  nonce: string;
  expiresAt: string;
  nodeId: string;
  respondingToNonce: string;
  signature: string;
  sentAt: string;
}

export interface MonoHandshakeResponseFrame {
  type: 'response';
  version: 1;
  sessionId: string;
  did: string;
  expiresAt: string;
  nodeId: string;
  respondingToNonce: string;
  signature: string;
  sentAt: string;
}

export interface MonoHandshakeResultFrame {
  type: 'result';
  version: 1;
  sessionId: string;
  accepted: boolean;
  verifiedAt?: string;
  error?: string;
}

export type MonoHandshakeErrorCode =
  | 'ERR_INVALID_FRAME'
  | 'ERR_SESSION_MISMATCH'
  | 'ERR_NONCE_MISMATCH'
  | 'ERR_DID_MISMATCH'
  | 'ERR_FRAME_EXPIRED'
  | 'ERR_CLOCK_SKEW'
  | 'ERR_REPLAY_DETECTED'
  | 'ERR_SIGNATURE_INVALID';

export interface MonoHandshakeAuditEvent {
  phase: 'challenge' | 'response';
  status: 'accepted' | 'rejected';
  code?: MonoHandshakeErrorCode;
  message: string;
  at: string;
}

export type MonoHandshakeStrictVerificationResult =
  | {
      ok: true;
      verifiedAt: string;
      events: MonoHandshakeAuditEvent[];
    }
  | {
      ok: false;
      code: MonoHandshakeErrorCode;
      message: string;
      verifiedAt: string;
      events: MonoHandshakeAuditEvent[];
    };

export type MonoHandshakeFrame =
  | MonoHandshakeHelloFrame
  | MonoHandshakeChallengeFrame
  | MonoHandshakeResponseFrame
  | MonoHandshakeResultFrame;
