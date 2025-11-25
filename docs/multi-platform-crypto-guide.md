# Goga 多端加密方案指南

本文档旨在为 Goga 加密网关提供一个统一的、跨平台的客户端加密实现规范。当前 `static/goga-crypto.js` 文件是为标准 Web 环境设计的，本文将以此为基础，阐述如何在微信小程序、原生 App (iOS, Android) 以及其他跨平台框架中实现相同的加密逻辑。

## 1. 核心加密规范

所有平台的实现都必须严格遵循以下加密规范，以确保与后端网关的兼容性。

- **算法**: `AES-GCM`
- **密钥长度**: 256位 (32字节)
- **IV (初始化向量)**: 12字节 (96位)。每次加密操作都必须生成一个全新的、密码学安全的随机IV。
- **认证标签 (Authentication Tag)**: 128位 (16字节)，由 AES-GCM 算法自动生成和验证。
- **密钥获取**: 通过向网关发送 `GET /goga/api/v1/key` 请求获取。响应体包含 `key` (Base64编码)、`token` 和 `ttl` (秒)。
- **客户端缓存**: 客户端应缓存密钥，有效期建议为 `ttl * 1000 * 0.8` 毫秒，以减少网络请求。

### 待加密的负载结构

在加密之前，需要将原始请求的 `Content-Type` 和 `body` 构造成一个特定的二进制负载：

```
[1-byte Content-Type 长度] + [UTF-8 编码的 Content-Type 字符串] + [UTF-8 编码的 Body 字符串]
```

**示例**:
- `Content-Type`: `application/json` (长度16)
- `Body`: `{"hello":"world"}`

二进制负载将是： `[16] + "application/json" + "{\"hello\":\"world\"}"`

### 最终加密荷载

加密后的数据需要按照以下结构进行组合和编码：

```
Base64( [12-byte IV] + [AES-GCM 加密后的二进制负载] )
```

这个 Base64 字符串将作为发往后端的 `encrypted` 字段的值，与 `token` 一起构成最终的请求体。

```json
{
  "token": "从 /key 接口获取的令牌",
  "encrypted": "上述 Base64 编码的加密结果"
}
```

---

## 2. 各平台实现指南

### a. Web (浏览器环境)

现有 `static/goga-crypto.js` 脚本是基准实现。它依赖 `window.crypto.subtle` API，并通过拦截 `fetch` 和 `XMLHttpRequest` 来自动处理加密。

**建议改进**:
- **模块化**: 可以将此脚本打包成一个标准的 NPM 模块（如 ES Module），方便在现代前端框架 (React, Vue, Angular) 中通过 `import` 使用，而不是作为全局脚本注入。
- **配置**: 保持 `window.gogaCryptoConfig` 的方式，允许开发者轻松排除特定 API 端点，避免不必要的加密。

### b. 微信小程序

微信小程序的运行环境与浏览器类似，但 API 有所不同。好消息是，较新的小程序基础库支持 `wx.crypto` 对象，其接口与 Web Crypto API (`window.crypto.subtle`) 兼容。

**实现步骤**:
1.  **检查 API 可用性**: 在使用前检查 `wx.crypto.subtle` 是否存在。
2.  **复用核心逻辑**: `goga-crypto.js` 中的 `encryptData` 函数几乎可以原样复用，只需将 `window.crypto` 替换为 `wx.crypto`。
3.  **网络请求**: 必须使用 `wx.request` API。由于无法像浏览器一样“拦截”所有请求，需要提供一个封装好的请求函数供业务代码调用。

**示例代码 (封装的加密请求函数)**:

```javascript
// 在小程序项目中, 创建一个 crypto-util.js 文件

// 假设 keyCache 和加密相关函数 (encryptData, getEncryptionKey 等) 已从 goga-crypto.js 适配过来
// 注意：getEncryptionKey 需要使用 wx.request 来请求密钥

/**
 * 发送加密的 POST 请求
 * @param {string} url - 请求的 URL
 * @param {object|string} data - 要发送的业务数据
 * @param {object} options - wx.request 的其他配置，如 header
 */
async function postEncrypted(url, data, options = {}) {
  try {
    const originalBody = typeof data === 'object' ? JSON.stringify(data) : data;
    const originalContentType = (options.header && options.header['Content-Type']) || 'application/json';

    // 构建与 Web 端规范一致的加密荷载
    const gogaPayload = await buildEncryptedPayload(originalBody, originalContentType);
    
    return new Promise((resolve, reject) => {
      wx.request({
        ...options,
        url: url,
        method: 'POST',
        data: gogaPayload, // 发送加密后的数据
        header: {
          ...options.header,
          'Content-Type': 'application/json;charset=UTF-8', // 网关需要此类型
        },
        success: resolve,
        fail: reject,
      });
    });

  } catch (error) {
    console.error('GoGa加密请求失败:', error);
    // 加密失败，可以选择降级为明文请求或直接失败
    // wx.request({ ... });
    throw error;
  }
}

module.exports = {
  postEncrypted
};
```
开发者在业务代码中，不再直接使用 `wx.request`，而是调用 `postEncrypted`。

### c. 原生 App (iOS & Android)

原生 App 应使用平台提供的、性能最优的加密 API 来重新实现加密规范。**不推荐**在原生 App 中嵌入 WebView 或 JavaScript 引擎来运行 JS 加密代码，因为这会带来性能损耗和额外的复杂性。

**iOS (Swift)**:
- **推荐框架**: `CryptoKit` (iOS 13+)。这是一个现代、安全的 Apple 官方加密框架。
- **实现要点**:
  - 使用 `AES.GCM.seal()` 方法进行加密。它会返回一个 `AES.GCM.SealedBox` 对象，其中包含 `ciphertext`, `tag` 和 `nonce` (IV)。
  - 必须将 `nonce` (IV) 和 `ciphertext` 拼接起来，然后进行 Base64 编码，以匹配后端规范。
  - 使用 `URLSession` 或 `Alamofire` 等网络库来获取密钥和发送加密请求。

**伪代码 (Swift)**:
```swift
import CryptoKit

func encryptAndSendData(data: Data, contentType: String) async throws {
    // 1. 获取 key 和 token
    let (key, token) = try await getEncryptionKey() // Base64 key
    let aesKey = SymmetricKey(data: Data(base64Encoded: key)!)

    // 2. 构建二进制负载
    var payload = Data()
    payload.append(UInt8(contentType.utf8.count))
    payload.append(contentsOf: contentType.utf8)
    payload.append(data)

    // 3. 加密
    let sealedBox = try AES.GCM.seal(payload, using: aesKey, nonce: AES.GCM.Nonce())
    
    // 4. 组合 IV 和 Ciphertext
    let finalPayload = sealedBox.nonce.withUnsafeBytes { $0 } + sealedBox.ciphertext
    let encryptedBase64 = finalPayload.base64EncodedString()

    // 5. 发送请求
    let gogaBody = ["token": token, "encrypted": encryptedBase64]
    // ... 使用 URLSession 发送 gogaBody
}
```

**Android (Kotlin / Java)**:
- **推荐框架**: `javax.crypto.Cipher`。这是标准的 Java 加密架构 (JCA)。
- **实现要点**:
  - 使用 `Cipher.getInstance("AES/GCM/NoPadding")` 获取 Cipher 实例。
  - 需要手动生成 12 字节的 IV，并使用 `GCMParameterSpec` 进行初始化。
  - 加密后，将 IV 和密文拼接，然后进行 Base64 编码。
  - 使用 `OkHttp` 或 `Retrofit` 等网络库。

**伪代码 (Kotlin)**:
```kotlin
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom
import android.util.Base64

fun encryptAndSendData(data: ByteArray, contentType: String) {
    // 1. 获取 key 和 token
    val (key, token) = getEncryptionKey() // Base64 key
    val aesKey = SecretKeySpec(Base64.decode(key, Base64.DEFAULT), "AES")

    // 2. 构建二进制负载
    val payload = byteArrayOf(contentType.length.toByte()) + contentType.toByteArray() + data

    // 3. 加密
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
    val gcmSpec = GCMParameterSpec(128, iv) // 128 bit tag length
    cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec)
    val encryptedData = cipher.doFinal(payload)

    // 4. 组合 IV 和 Ciphertext
    val finalPayload = iv + encryptedData
    val encryptedBase64 = Base64.encodeToString(finalPayload, Base64.NO_WRAP)

    // 5. 发送请求
    val gogaBody = mapOf("token" to token, "encrypted" to encryptedBase64)
    // ... 使用 OkHttp 发送 gogaBody
}
```

### d. 跨平台框架 (Kotlin Multiplatform, Flutter等)

**Kotlin Multiplatform (KMP)**:
这是实现跨平台加密的 **理想选择**。
- 可以在 `commonMain` 模块中编写一次加密/解密、网络请求和密钥管理的逻辑。
- 对于加密实现，可以使用 `expect/actual` 机制，让 `commonMain` 定义预期的加密函数，然后在 `androidMain` 和 `iosMain` 中分别使用 `javax.crypto` 和 `CryptoKit` 提供实际的平台实现。这样既能共享绝大部分逻辑，又能利用各平台的原生最佳实践。

**Flutter**:
- 使用 Dart 社区提供的加密库，如 `cryptography` 或 `pointycastle`。
- 在 Dart 中重新实现加密规范中定义的逻辑。
- 使用 `http` 或 `dio` 包进行网络请求。
- 确保所选库支持 AES-GCM 模式，并能自定义 IV。

```