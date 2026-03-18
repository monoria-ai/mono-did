# mono-did

`mono-did` 是从 Monoclaw 拆出来的 DID 与握手基础能力库，目标是：

- 提供可复用的身份与握手语义（与具体业务解耦）
- 支持本地防重放 + 可插拔的全局 nonce claim
- 支持 DID key event log（创建/轮换/吊销）与事件传播接口
- 让 Monoclaw/OpenClaw 或其他项目通过稳定接口接入

## 设计边界

`mono-did` 提供的是协议语义与验证逻辑，不内置区块链/BFT 共识网络。

- 在没有共识层时：是最终一致（eventual consistency）
- 要实现全网强一致：需要外接共识系统（联盟 BFT / 链）

这条边界是刻意设计：

- `mono-did` 负责“事件如何被签名和验证”
- 共识网络负责“事件在全网的唯一顺序与最终确认”

## 包结构

```
packages/
  mono-did        # 统一入口包，聚合导出所有核心能力
  did-core-types   # 核心类型：DID、握手、event log
  mono-identity    # 身份创建/解析/签名验签 + DID event log + gossip 接口
  mono-handshake   # challenge-response 握手 + 本地防重放 + 全局 nonce claim 接口
  mono-protocol    # 传输协议常量与 JSONL 编解码
  mono-adapters    # 稳定适配器入口（identity/handshake/protocol）
tests/unit         # 单元测试
```

## 核心能力一览

### 1) 身份层（DID）

来自 `@mono/identity`：

- `createDidPeerIdentity`：创建 `did:peer:2` 身份
- `resolveDidPeer2`：解析 DID Document
- `signPayload` / `verifyPayload`：Ed25519 签名验签
- `createMultikeyFromPublicKeyPem` / `publicKeyPemFromMultikey`

### 2) DID Key Event Log

来自 `@mono/identity` + `@mono/did-core-types`：

- 事件类型：`create | rotate | revoke`
- 每个事件包含：`version` + `prevHash` + `signature` + `nodeId` + `createdAt`
- `verifyDidKeyEventLog`：校验链式完整性、签名和吊销后状态
- `applyDidKeyEvent`：将外部事件应用到本地日志并强校验

### 3) 握手层（challenge-response）

来自 `@mono/handshake`：

- `createServerChallengeFrame` / `createClientResponseFrame`
- `verifyServerChallengeFrameStrict` / `verifyClientResponseFrameStrict`
- challenge/response 签名绑定字段：
  - `sessionId`
  - `nonce`
  - `expiresAt`
  - `nodeId`
- 本地防重放：`MonoHandshakeReplayStore`
- 全局 nonce claim 接口：`MonoHandshakeGlobalNonceClaimStore`

### 4) 传输协议

来自 `@mono/protocol`：

- 协议标识：`/mono/handshake/1.0.0`
- JSONL 编码：`encodeFrame` / `decodeFrame`

## 安装

> 下方以 npm 公有包为例。你也可以发布到私有 registry。

### 统一安装（推荐）

```bash
npm i @mono/did
```

一个入口即可拿到 identity/handshake/protocol/adapters 的全部导出。

### 按需安装（子包）

```bash
npm i @mono/did-core-types @mono/identity @mono/handshake @mono/protocol @mono/adapters
```

## 快速开始

### 0) 统一入口包

```ts
import { createDefaultMonoAdapters, createDidPeerIdentity } from '@mono/did';

const adapters = createDefaultMonoAdapters();
const identity = await createDidPeerIdentity();
```

### 1) 基础身份与握手

```ts
import { createDidPeerIdentity, createNonce } from '@mono/identity';
import {
  createHandshakeSessionId,
  createServerChallengeFrame,
  createClientResponseFrame,
  verifyServerChallengeFrameStrict,
  verifyClientResponseFrameStrict,
  InMemoryHandshakeReplayStore,
} from '@mono/handshake';

const initiator = await createDidPeerIdentity();
const responder = await createDidPeerIdentity();
const replayStore = new InMemoryHandshakeReplayStore();

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

const challengeResult = verifyServerChallengeFrameStrict(
  { hello, challenge },
  { replayStore, now: new Date().toISOString() },
);
if (!challengeResult.ok) throw new Error(challengeResult.code);

const response = createClientResponseFrame({
  hello,
  challenge,
  initiatorIdentity: initiator,
});

const responseResult = verifyClientResponseFrameStrict(
  { hello, challenge, response },
  { replayStore, now: new Date().toISOString() },
);
if (!responseResult.ok) throw new Error(responseResult.code);
```

### 2) DID Key Event Log（创建/轮换/吊销）

```ts
import {
  createDidPeerIdentity,
  createDidKeyEventLog,
  appendDidRotateKeyEvent,
  appendDidRevokeKeyEvent,
  verifyDidKeyEventLog,
} from '@mono/identity';

const identity = await createDidPeerIdentity();

let log = createDidKeyEventLog(identity, { nodeId: 'node-a' });

log = appendDidRotateKeyEvent(
  log,
  identity,
  { publicKeyMultibase: identity.publicKeyMultibase, keyId: `${identity.did}#key-next` },
  { nodeId: 'node-a', reason: 'scheduled-rotation' },
);

log = appendDidRevokeKeyEvent(log, identity, {
  nodeId: 'node-a',
  reason: 'identity-decommissioned',
});

const verification = verifyDidKeyEventLog(log);
if (!verification.ok) throw new Error(`${verification.code}: ${verification.message}`);
```

### 3) 接入“全局 nonce claim”（强一致所需）

`mono-did` 不实现共识，但提供接入点。你需要把 claim 写入你自己的强一致存储/共识层：

```ts
import type { MonoHandshakeGlobalNonceClaimStore } from '@mono/handshake';
import { verifyServerChallengeFrameStrictWithConsensus } from '@mono/handshake';

class MyConsensusNonceStore implements MonoHandshakeGlobalNonceClaimStore {
  async claim(claimKey: string, expiresAtMs: number, nowMs: number): Promise<boolean> {
    // 伪代码：提交到 BFT/链，若 claimKey 已存在返回 false
    // return consensusTx('nonce-claim', { claimKey, expiresAtMs, nowMs });
    return true;
  }
}

const result = await verifyServerChallengeFrameStrictWithConsensus(
  { hello, challenge },
  {
    globalNonceClaimStore: new MyConsensusNonceStore(),
    globalClaimNamespace: 'prod-cluster-a',
  },
);
```

## 适配器入口（推荐业务侧使用）

`@mono/adapters` 提供稳定入口：

```ts
import { createDefaultMonoAdapters } from '@mono/adapters';

const adapters = createDefaultMonoAdapters();
const id = await adapters.identity.createIdentity();
const sessionId = adapters.handshake.createSessionId();
const encoded = adapters.protocol.encodeFrame({ hello: 'world' });
```

适配器优点：

- 业务层依赖固定接口，不直接耦合底层包
- 后续升级实现细节时，上层改动更小

## 去中心化与一致性说明

### 无共识层（当前最常见）

- 可以做：本地防重放、签名验证、gossip 传播
- 不能做：全网“严格一次”防重放、吊销强一致瞬时生效

### 有共识层（目标形态）

- 将 `nonce-claim` 与 DID key events 写入共识日志
- 只接受 finalized 结果作为业务判定
- 才能实现全网强一致语义

## 生产建议

1. 密钥管理  
将私钥放入 KMS/HSM，不要明文落盘。

2. 时钟同步  
所有节点必须启用 NTP，避免 `expiresAt` 与时钟偏差导致误判。

3. 防重放存储  
`InMemoryHandshakeReplayStore` 仅用于 demo/单进程；生产应使用持久化共享存储（如 Redis）。

4. 审计与追踪  
保存握手验证事件、event-log 校验结果、claim 结果与链上高度（如有）。

5. 错误处理  
严格区分协议错误（如 `ERR_NONCE_MISMATCH`）与系统错误（网络/存储超时）。

## 非目标（当前版本）

- 不内置区块链/BFT 实现
- 不包含业务授权策略（工具白名单、目录白名单、速率限制）
- 不包含 UI 状态管理

## 本地开发

```bash
pnpm install
pnpm test
pnpm typecheck
pnpm build
```

## 发布

仓库已接入 Changesets：

```bash
pnpm changeset
pnpm version-packages
pnpm release
```

## 社区与治理

- 贡献指南: [CONTRIBUTING.md](./CONTRIBUTING.md)
- 行为准则: [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md)
- 安全报告: [SECURITY.md](./SECURITY.md)
- 许可证: [LICENSE](./LICENSE)

## License

MIT
