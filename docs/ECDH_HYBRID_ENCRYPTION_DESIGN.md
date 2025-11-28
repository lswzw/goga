# GoGa ECDH 混合加密双向通信设计文档

## 1. 架构概述

本文档描述了 GoGa 系统中已实现的 ECDH 混合加密双向通信架构。该系统利用 ECDH非对称加密技术安全地交换会话密钥，随后使用 AES-GCM 对称加密来保护实际的业务数据通信，从而为客户端与服务器之间的请求和响应提供端到端的安全保障。

### 1.1 设计原则

- **安全性**: 采用业界认可的标准加密算法（ECDH P-256, AES-256-GCM, HKDF-SHA256）确保通信的机密性和完整性。
- **前向保密**: 每个通信会话都使用临时的、独立派生的密钥，确保单个会话密钥的泄露不影响过去或未来的通信安全。
- **性能**: 将消耗较大的非对称加密操作仅限于初始的密钥交换阶段，实际数据传输采用高性能的对称加密。
- **透明性**: 加密和解密过程通过客户端拦截器和服务器中间件自动完成，对应用层透明。

### 1.2 核心架构

本架构的核心特点是**双重加密**：不仅业务数据本身被加密，用于解密的初始化向量 (IV) 也被加密传输，进一步增强了系统的安全性。

1.  **密钥交换**: 客户端和服务器通过一次性的 ECDH 密钥交换，生成一个共享密钥。
2.  **密钥派生 (HKDF)**: 从共享密钥中派生出独立的 `requestKey`（用于加密请求）和 `responseKey`（用于加密响应）。
3.  **加密（客户端 -> 服务器）**:
    *   客户端生成一个随机的 **IV**。
    *   使用 `requestKey` 和随机 **IV** 加密业务数据，得到 `encryptedData`。
    *   使用 `requestKey` 再次加密 **IV** 本身，得到 `encryptedIV`。
    *   将 `sessionId`, `encryptedData`, `encryptedIV` 等信息组合成 JSON 载荷发送。
4.  **解密（服务器）**:
    *   服务器使用 `sessionId` 找到对应的 `requestKey`。
    *   首先解密 `encryptedIV` 得到原始的 **IV**。
    *   然后使用 `requestKey` 和解密后的 **IV** 解密 `encryptedData`。
5.  响应的加解密流程与上述过程类似，但使用 `responseKey`。

## 2. 详细设计

### 2.1 密钥交换

#### 2.1.1 协议与算法

- **密钥交换协议**: 椭圆曲线迪菲-赫尔曼 (ECDH)
- **椭圆曲线**: `P-256` (secp256r1)
- **密钥派生函数**: HKDF-SHA256 (RFC 5869)

#### 2.1.2 密钥交换端点

- **URL**: `/goga/api/v1/key-exchange`
- **Method**: `POST`
- **请求格式**:
  ```json
  {
      "clientPublicKey": "base64编码的客户端公钥"
  }
  ```
- **响应格式**:
  ```json
  {
      "serverPublicKey": "base64编码的服务器公钥",
      "sessionId": "会话ID",
      "ttl": 600
  }
  ```

#### 2.1.3 密钥派生

通过 HKDF 从 ECDH 共享密钥中派生出以下三个独立的密钥，存储在会话中：
- `RequestKey`: 32字节，用于加密从客户端到服务器的数据（以及IV）。
- `ResponseKey`: 32字节，用于加密从服务器到客户端的数据（以及IV）。
- `MACKey`: 32字节，预留用于未来的消息认证码功能。

### 2.2 加密通信

#### 2.2.1 对称加密算法

- **算法**: AES-256-GCM (提供认证加密)
- **IV 长度**: 12 字节

#### 2.2.2 加密消息格式

客户端请求和服务器响应均使用统一的 JSON 载荷格式。

- **加密请求/响应格式**:
  ```json
  {
      "version": "1.0",
      "sessionId": "会话ID",
      "encryptedData": "base64编码的加密业务数据",
      "encryptedIV": "base64编码的加密IV",
      "ivLength": 12
  }
  ```

#### 2.2.3 加密流程 (客户端)

1.  确保已通过密钥交换建立有效会话，并获取了 `sessionId` 和 `requestKey`。
2.  准备原始业务数据（例如，JSON 字符串）。
3.  生成一个 12 字节的随机 **IV**。
4.  使用 `requestKey` 和此 **IV** 对原始业务数据进行 AES-GCM 加密，生成 `encryptedData`。
5.  使用 `requestKey` 对 **IV** 本身进行 AES-GCM 加密（此过程也需要一个随机生成的临时IV），生成 `encryptedIV`。
6.  将 `sessionId`, `encryptedData` (Base64编码), `encryptedIV` (Base64编码) 和 `ivLength` 组装成 JSON 对象作为请求体。
7.  发送该 POST 请求到目标业务API。

#### 2.2.4 解密流程 (服务器)

1.  `ECDDecryptionMiddleware` 拦截到请求。
2.  解析 JSON 请求体，提取 `sessionId`, `encryptedData`, `encryptedIV`。
3.  使用 `sessionId` 从 `session.Manager` 中查找会话，获取 `requestKey`。
4.  使用 `requestKey` 解密 `encryptedIV`，得到原始的 **IV**。
5.  使用 `requestKey` 和解密出的 **IV** 对 `encryptedData` 进行解密，得到原始业务数据。
6.  将解密后的数据放回请求体，并将请求传递给后续的业务处理器。

*注：服务器响应的加密流程与客户端加密类似，但使用 `responseKey`。客户端解密响应的流程与服务器解密类似，但使用 `responseKey`。*

## 3. 会话管理

### 3.1 会话生命周期

- **创建**: 客户端首次调用 `/goga/api/v1/key-exchange` 端点时创建。
- **存储**: 会话信息（包括派生密钥）存储在服务器内存中，由 `internal/session/manager.go` 管理。
- **使用**: 客户端在每个加密请求中携带 `sessionId` 来标识使用的会话和密钥。
- **过期与清理**: 会话具有预设的生存时间 (TTL)。过期的会话会由会话管理器定期清理，以释放资源。客户端需要重新发起密钥交换来建立新会话。

### 3.2 安全考虑

- **密钥隔离**: 每个会话的密钥都是独立派生的，确保会话之间的安全隔离。
- **内存安全**: 会话密钥仅存储在服务器内存中，不会持久化。进程重启后所有会话失效。
- **会话劫持风险**: `sessionId` 的泄露可能导致会话被劫持。为缓解此风险，通信必须在 TLS/HTTPS 通道上进行。

## 4. 实施状态

根据 `ECDH_HYBRID_ENCRYPTION_TASKS.md`，该架构的核心功能已经完成开发和集成。

- **前端**: `static/goga.js` 已包含 ECDH 密钥交换、会话管理、AES 加密和请求拦截器的全部逻辑。
- **后端**: 相关的 `internal/crypto`、`internal/session`、`internal/gateway` 和 `internal/middleware` 模块已实现该架构。
- **接口**: 已统一使用 `/goga/api/v1/key-exchange` 作为唯一的密钥交换接口。

---
**版本历史**:

| 版本 | 日期 | 作者 | 更改描述 |
|:---|:---|:---|:---|
| 1.0 | 2025-11-28 | AI | 初始版本，描述了基于 Token 的旧加密方案。 |
| 2.0 | 2025-11-28 | AI | 根据 `TASKS.md` 中已实施的架构重写文档，同步了密钥交换流程、加密消息格式和核心设计原则。 |
