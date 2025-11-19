# GoGa - 系统设计文档

## 1. 概述

本文档是 GoGa（Go Gateway）项目的技术设计说明，旨在将需求文档中的功能和非功能性需求转化为具体的架构和模块设计，以指导后续的开发工作。

### 1.1. 总体架构

GoGa 作为一个反向代理网关，部署在客户端（浏览器）和后端业务应用之间。它的核心任务是拦截、处理、并转发 HTTP 流量，对特定请求进行加解密操作。

**架构图:**

```
               +----------------------+      +--------------------------+      +--------------------+
               |                      |      |                          |      |                    |
   Browser  <--|--(HTTPS)-----------> |  GoGa Gateway (本项目)   |----->| Backend Application|
 (Client)      |                      |      |                          |      |                    |
               +----------------------+      +-----------+--------------+      +--------------------+
                                                         |
                                                         |
                                                         | (模块)
                                           +-------------+-------------+
                                           |      HTTP Middleware      |
                                           +-------------+-------------+
                                           |  1. Logging & Recovery    |
                                           |  2. Decryption Handler    |
                                           |  3. Reverse Proxy Handler |
                                           |  4. Script Injection      |
                                           +---------------------------+
```

### 1.2. 请求处理生命周期

1.  **静态资源请求 (GET)**：
    *   客户端向 GoGa 发起请求（例如 `GET /style.css`）。
    *   GoGa 将请求直接转发给后端业务应用。
    *   后端应用返回响应。
    *   如果响应是 HTML (`Content-Type: text/html`)，GoGa 的脚本注入中间件会向响应体中插入加密脚本的引用。
    *   如果响应是其他静态资源，GoGa 直接将其返回给客户端。

2.  **加密表单提交 (POST)**：
    *   用户在浏览器中提交表单。
    *   页面中被注入的 JS 脚本拦截 `submit` 事件。
    *   JS 脚本向 GoGa 的一个专用 API (`/goga/api/v1/key`) 请求一个一次性加密密钥。
    *   JS 脚本使用获取到的密钥将表单数据加密成一个 JSON 载荷。
    *   JS 脚本使用 `fetch` 将该加密载荷发送到原始的表单 `action` URL。
    *   GoGa 的解密中间件识别出这是一个加密请求。
    *   网关使用缓存的密钥进行解密。
    *   解密成功后，网关将请求体还原为原始的表单数据格式 (`application/x-www-form-urlencoded` 或 `application/json`)。
    *   还原后的明文请求被转发到后端业务应用。
    *   后端返回的响应按原路返回给客户端。

## 2. 核心组件设计

系统将采用模块化的设计，核心逻辑通过一系列的 HTTP 中间件（Middleware）来实现。

### 2.1. 配置管理

*   **实现方式**: 使用 [Viper](https://github.com/spf13/viper) 库进行配置管理。
*   **配置源**:
    1.  **配置文件**: `configs/config.yaml`（默认）。
    2.  **环境变量**: 拥有更高优先级，用于覆盖配置文件中的同名配置项。环境变量需加上前缀，例如 `GOGA_ENCRYPTION_KEY`。
*   **核心配置项**:
    ```yaml
    # 服务监听端口
    server:
      port: "8080"
      tls_cert_path: "" # TLS 证书路径
      tls_key_path: ""  # TLS 私钥路径

    # 后端业务应用地址
    backend_url: "http://localhost:3000"

    # 加密相关配置
    encryption:
      enabled: true # 全局开关，false 则退化为纯反向代理
      master_key: "" # 主密钥 (Base64 编码)
      key_cache_ttl_seconds: 60 # 一次性密钥在服务端的缓存时间

    # 日志级别 (debug, info, warn, error)
    log_level: "info"
    ```

### 2.2. 主服务与 HTTP 中间件链

GoGa 的核心是一个标准的 Go `http.Server`。所有请求都将经过一个预定义的中间件链。

*   **实现方式**: 使用 Go 语言的装饰器模式，将 `http.Handler` 进行层层包装。
*   **中间件执行顺序**:
    1.  **Panic Recovery**: 捕获任何后续处理中发生的 `panic`，防止服务崩溃，并返回 `500 Internal Server Error`。
    2.  **Logging**: 记录每个请求的基本信息，如方法、路径、状态码和处理耗时。
    3.  **Health Check**: 拦截 `/healthz` 路径，直接返回 `200 OK`，用于健康检查。
    4.  **API Handler**: 拦截 `/goga/api/*` 和 `/goga-crypto.js` 路径，由内部 API 处理器提供服务（如分发密钥和 JS 脚本）。
    5.  **Decryption Middleware**: 处理传入的加密请求，进行解密。
    6.  **Reverse Proxy Handler**: 将请求（可能已被解密）转发到后端。该处理器本身会处理响应。
    7.  **Script Injection Middleware**: 在 `Reverse Proxy Handler` 内部，当接收到后端响应后，执行脚本注入逻辑。

### 2.3. 反向代理模块

*   **实现方式**: 使用 Go 标准库 `net/http/httputil.ReverseProxy`。
*   **功能**:
    *   将请求无缝转发到 `config.backend_url`。
    *   自动处理 `X-Forwarded-For`, `X-Forwarded-Host` 等标准代理头部。
    *   响应的处理逻辑（如脚本注入）将通过 `ReverseProxy.ModifyResponse` 钩子函数实现。

### 2.4. 响应处理与脚本注入中间件

此逻辑作为 `ReverseProxy.ModifyResponse` 的一部分实现。

*   **触发条件**: 当后端响应头 `Content-Type` 包含 `text/html` 时。
*   **实现步骤**:
    1.  读取响应体 `response.Body` 的所有内容。
    2.  将响应体内容转换为字符串，查找 `</body>` 标签。
    3.  在 `</body>` 之前插入 `<script src="/goga-crypto.js" defer></script>`。
    4.  创建一个新的 `io.ReadCloser` 来包装修改后的响应体内容。
    5.  更新响应头 `Content-Length` 为新响应体的长度。
    6.  将新的响应体设置回 `response.Body`。
*   **脚本服务**: 网关需要提供一个路由来服务加密脚本本身。
    *   **Endpoint**: `GET /goga-crypto.js`
    *   **内容**: 一个预先编译或静态的 JavaScript 文件。

### 2.5. 请求解密中间件

*   **触发条件**:
    *   请求方法为 `POST`。
    *   请求头 `Content-Type` 为 `application/json`。
    *   请求体可以被解析为 `{"token": "...", "encrypted": "..."}` 的格式。
*   **实现步骤**:
    1.  解析请求体，获取 `token` 和 `encrypted` 数据。
    2.  使用 `token` 在服务端的密钥缓存（一个带过期时间的 `map`）中查找对应的一次性加密密钥 (`ONETIME_KEY`)。
    3.  **密钥未找到**: 如果 `token` 不存在或已过期，立即返回 `400 Bad Request`，并记录错误。
    4.  **密钥找到**:
        *   从缓存中删除该 `token`，确保一密钥一用。
        *   对 `encrypted` 字段进行 Base64 解码。
        *   使用 `ONETIME_KEY` 通过 `AES-256-GCM` 算法解密数据。
        *   **解密失败**: 返回 `400 Bad Request`。
        *   **解密成功**:
            *   将解密后的明文（原始的表单数据）重新包装。
            *   根据明文的原始格式，将请求的 `Content-Type` 恢复为 `application/x-www-form-urlencoded` 或 `application/json`。
            *   更新请求体和 `Content-Length`，然后将请求传递给下一个中间件（反向代理）。

### 2.6. 客户端加密脚本 (`goga-crypto.js`)

这是一个静态 JS 文件，将在所有 HTML 页面中运行。

*   **核心逻辑**:
    1.  **事件监听**: 使用 `document.addEventListener('submit', handler, true)` 在捕获阶段拦截所有表单的 `submit` 事件。
    2.  **拦截与阻止**: 在 `handler` 中，调用 `event.preventDefault()` 来阻止表单的默认提交行为。
    3.  **获取一次性密钥**:
        *   立即调用 `fetch('/goga/api/v1/key')` 向网关请求加密配置。
        *   API 返回 `{"key": "BASE64_ENCODED_KEY", "token": "UNIQUE_TOKEN"}`。
    4.  **数据序列化**:
        *   使用 `new FormData(formElement)` 获取表单数据。
        *   将 `FormData` 转换为一个简单的 JSON 对象。
    5.  **加密**:
        *   使用浏览器内置的 `SubtleCrypto` API 或引入的第三方库（如 `crypto-js`）执行 `AES-256-GCM` 加密。
        *   将序列化后的 JSON 数据作为明文进行加密。
    6.  **构造载荷**: 创建加密后的请求体 `{"token": "UNIQUE_TOKEN", "encrypted": "BASE64_ENCODED_CIPHERTEXT"}`。
    7.  **发送加密数据**:
        *   使用 `fetch` 将此加密载荷以 `POST` 方法发送到原始表单的 `action` 属性指定的 URL。
        *   设置请求头 `Content-Type: application/json`。

### 2.7. 密钥管理与分发

这是系统的安全核心。

*   **主密钥 (`MASTER_KEY`)**:
    *   一个 32 字节（256位）的密钥，用于内部敏感数据的保护，但 **绝不直接参与** 前后端数据的加解密。
    *   通过环境变量 `GOGA_ENCRYPTION_KEY` (Base64 编码) 或配置文件加载。
*   **一次性会话密钥 (`ONETIME_KEY`)**:
    *   **生成**: 当客户端 JS 请求 `/goga/api/v1/key` 时，服务器动态生成一个 32 字节的随机密钥。
    *   **分发**:
        *   服务器同时生成一个唯一 `token` (例如 UUID)。
        *   在服务器端的内存缓存中存储 `[token]: ONETIME_KEY`，并设置 TTL（例如 60 秒）。
        *   将 `ONETIME_KEY` (Base64 编码) 和 `token` 返回给客户端。
    *   **安全性**: `ONETIME_KEY` 的传输依赖于 `HTTPS` 提供的信道安全。它生命周期极短，且只能使用一次，有效降低了密钥泄露的风险。

## 3. 数据流与协议

### 3.1. 加密数据包格式

客户端加密后，发送给网关的请求体格式如下：

```json
{
  "token": "d8e8fca2-c2e8-48a3-a388-32b0d32c8e1a",
  "encrypted": "BASE64_ENCODED(NONCE + AES_GCM_CIPHERTEXT)"
}
```

*   **token**: 由网关在分发密钥时提供，用于在解密时快速查找密钥。
*   **encrypted**: 加密数据的 Base64 编码。密文本身由 `AES-GCM` 生成的 `nonce` 和加密数据拼接而成。

## 4. 非功能性设计

### 4.1. 性能
*   **加解密**: `AES-GCM` 在现代 CPU 上有硬件加速，性能开销极低。
*   **资源**:
    *   使用 `sync.Pool` 复用缓冲区，减少内存分配和 GC 压力。
    *   Go 的并发模型非常适合处理高并发的 I/O 密集型任务。
*   **延迟**: 客户端获取密钥会引入一次额外的 RTT。JS 脚本应在页面加载后立即预取密钥，而不是等到用户提交时才获取，从而将此延迟对用户体验的影响降到最低。

### 4.2. 安全
*   **TLS**: 强制启用 HTTPS 是保障所有通信（包括密钥分发）安全的前提。配置中必须提供 TLS 证书和私钥路径。
*   **密钥管理**:
    *   主密钥从不离开服务器。
    *   一次性密钥生命周期短，用后即焚。
*   **输入验证**: 对所有来自客户端的输入（如加密载荷）进行严格的格式和类型校验。

### 4.3. 可用性与监控
*   **健康检查**: 提供 `GET /healthz` 端点，返回 `200 OK`，方便与 Kubernetes、Consul 或其他负载均衡器集成。
*   **旁路模式**: 将 `encryption.enabled` 配置为 `false`，GoGa 将作为一个纯粹的反向代理运行，所有加解密逻辑都将被跳过。这可用于紧急故障排查或性能对比测试。

## 5. v1.0 范围与限制
*   **方法与内容类型**: 解密中间件仅处理 `POST` 请求，且 `Content-Type` 为 `application/json`（因为加密载荷是此格式）。
*   **暂不处理**:
    *   `GET` 请求的参数加密。
    *   `multipart/form-data` 文件上传。
    *   WebSocket 流量。
*   **密钥缓存**: 初始版本将使用 Go 内置的带过期时间的 `map` 作为密钥缓存，适用于单实例部署。在集群环境下，需要替换为外部共享缓存，如 Redis。