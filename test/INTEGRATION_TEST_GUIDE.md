# GoGa 集成测试指南

本文档旨在指导如何运行 GoGa 项目的集成测试，并解释每个测试用例的预期结果。

## 前提条件

- 已安装 Go 语言环境 (版本 1.18+)
- 确保您的 Go 模块依赖是最新的。如果遇到构建错误，请尝试运行 `go mod tidy`。

## 如何运行集成测试

要运行所有集成测试，请在项目根目录（包含 `go.mod` 文件的目录）下执行以下命令：

```bash
go test -v ./test/...
```

`-v` 标志会显示每个测试的详细输出。

## 集成测试用例及其预期效果

以下是 `test/e2e_encryption_test.go` 中定义的各个集成测试及其成功的预期结果：

### `TestFullEncryptionFlow`

**描述**: 这个测试模拟了 GoGa 网关的完整加密和解密流程，从 HTML 页面加载到客户端提交加密数据，再到后端收到解密后的明文。

**预期效果**:
- 当访问 HTML 页面 (`/some-html`) 时，响应中应该成功注入 `<script src="/goga-crypto.min.js" defer></script>` 标签。
- 能够成功从 `/goga/api/v1/key` 端点获取加密密钥和令牌，并且 TTL (Time-To-Live) 大于 0。
- 模拟客户端使用获取到的密钥和令牌加密表单数据 (`username=admin`, `password=password`) 并提交到 `/api/login`。
- GoGa 网关应该成功解密请求，并以 `application/x-www-form-urlencoded` 的 `Content-Type` 将原始明文数据 (`username=admin&password=password`) 转发给模拟后端。
- 模拟后端应该收到正确的、未经修改的明文数据，并返回 `200 OK`。
- 访问非 HTML 内容 (`/other-content`) 时，不应该注入脚本。

### `TestInvalidToken`

**描述**: 这个测试验证当客户端提交无效或过期的加密令牌时，GoGa 网关的安全处理行为。

**预期效果**:
- 当客户端使用一个不存在或已过期的令牌提交加密数据时，GoGa 网关应该返回 `401 Unauthorized` HTTP 状态码。
- 模拟后端不应该收到任何请求，表明 GoGa 在解密中间件中成功拦截了无效请求。

### `TestEncryptionDisabledFlow`

**描述**: 这个测试验证当 GoGa 配置中禁用加密功能时，网关的行为，特别是脚本注入和请求代理。

**预期效果**:
- 当访问 HTML 页面 (`/some-html`) 时，GoGa 网关不应该向响应中注入任何加密脚本 (`goga-crypto.min.js`)。
- 客户端提交的标准 POST 请求（例如 JSON 格式）应该未经修改地成功通过 GoGa 网关，并被代理到模拟后端。
- 模拟后端应该收到原始的 `application/json` 类型的请求体，并返回 `200 OK`。

### `TestStaticAssetDelivery`

**描述**: 这个测试验证 GoGa 网关是否正确地提供其自身的静态加密脚本文件 (`goga-crypto.min.js`)。

**预期效果**:
- 当客户端请求 `/goga-crypto.min.js` 时，GoGa 网关应该返回 `200 OK` HTTP 状态码。
- 响应的 `Content-Type` 头部应该包含 `"text/javascript"`，表明它是一个 JavaScript 文件。
- 响应体不应该为空，即文件内容被成功提供。

### `TestHealthCheck`

**描述**: 这个测试验证 GoGa 网关的健康检查端点 (`/healthz`) 是否按预期工作。

**预期效果**:
- 当客户端（通常是本地主机）请求 `/healthz` 时，GoGa 网关应该返回 `200 OK` HTTP 状态码。
- 响应体应该精确地是字符串 `"OK"`。
- **注意**: 由于安全限制，`/healthz` 端点仅响应来自本地回环地址 (`127.0.0.1` 或 `::1`) 的请求。测试环境会自动满足此条件。
