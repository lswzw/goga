# GoGa - 基于 Go 的零侵入 Web 表单加密网关

GoGa 是一个基于 Go 语言实现的高性能反向代理网关。其核心目标是在不侵入现有任何前端或后端业务系统的前提下，透明地实现对 Web 表单提交数据的应用层加密，从而增强数据在传输链路中的安全性。

## 核心特性

- **零侵入式代理**: 作为标准反向代理运行，无需修改任何现有 Web 应用的代码。
- **动态脚本注入**: 自动向 HTML 页面注入加密所需的 JavaScript 脚本，对前端透明。
- **客户端自动加密**: 注入的脚本自动拦截表单提交事件，并使用 `AES-256-GCM` 算法在数据发送前进行加密。
- **网关透明解密**: 网关在将请求转发到后端服务前，自动解密请求数据，后端服务无感知。
- **高度可配置**: 支持通过 YAML 配置文件和环境变量进行灵活配置，包括后端地址、端口、加密密钥等。
- **安全设计**: 采用短生命周期、一次性使用的对称密钥进行数据加密，并依赖 HTTPS 保障信道安全。

## 架构简介

GoGa 部署在客户端（浏览器）和您的后端业务应用之间。它通过一系列的 HTTP 中间件来处理所有流量。

```
               +----------------------+      +--------------------------+      +--------------------+
               |                      |      |                          |      |                    |
   Browser  <--|--(HTTPS)-----------> |  GoGa Gateway (本项目)   |----->| Backend Application|
 (Client)      |                      |      |                          |      |                    |
               +----------------------+      +-----------+--------------+      +--------------------+
                                                         |
                                                         | (中间件链)
                                           +-------------+-------------+
                                           |  1. 日志 & 恢复            |
                                           |  2. 解密处理器             |
                                           |  3. 反向代理处理器         |
                                           |  4. 脚本注入器             |
                                           +---------------------------+
```

## 安装与运行

### 1. 先决条件
- [Go](https://golang.org/) (建议版本 1.18 或更高)

### 2. 配置
项目通过 `configs/config.yaml` 文件或环境变量进行配置。您可以复制 `configs/config.example.yaml` 并重命名。

**配置加载规则**:
1.  **默认值**: 代码中预设的默认值。
2.  **配置文件**: `configs/config.yaml` 或项目根目录下的 `config.yaml` 中的值会覆盖默认值。
3.  **环境变量**: 拥有最高优先级，会覆盖所有其他设置。环境变量需要加上 `GOGA_` 前缀，并用下划线 `_` 代替点 `.` (例如, `server.port` 对应 `GOGA_SERVER_PORT`)。

**主要配置项**:

```yaml
# configs/config.yaml

# 服务监听配置
server:
  # HTTP/HTTPS 监听端口
  port: "8080"
  
  # TLS/HTTPS 配置。如果 cert 和 key 的路径都提供了，网关将以 HTTPS 模式启动。
  # 否则，它将以标准的 HTTP 模式启动。
  tls_cert_path: "" 
  tls_key_path: ""

# 后端真实业务应用的地址
backend_url: "http://localhost:3000"

# 加密相关配置
encryption:
  # 全局开关，false 则退化为纯反向代理，可用于调试
  enabled: true 
  # 主密钥，用于内部加密操作。必须是一个 32 字节（256位）的密钥，经过 Base64 编码。
  # 强烈建议通过环境变量 GOGA_ENCRYPTION_KEY 提供，而不是硬编码在配置文件中。
  master_key: "" 
  # 一次性密钥在服务端的缓存时间（秒）
  key_cache_ttl_seconds: 60 

# 脚本注入相关配置
script_injection:
  # 注入到 HTML 响应中的 <script> 标签内容。
  script_content: '<script src="/goga-crypto.min.js" defer></script>'

# 日志级别 (debug, info, warn, error)
log_level: "info"
```

**重要**: 为了安全，`master_key` 强烈建议通过环境变量 `GOGA_ENCRYPTION_KEY` 提供。

### 3. 生成本地 TLS 证书 (用于测试)
在生产环境中，您应该使用由受信任的证书颁发机构（CA）签发的证书。但在本地开发和测试时，可以使用 `openssl` 快速生成自签名证书。

```bash
# 生成一个有效期为 365 天的自签名证书和私钥
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout configs/localhost.key.pem \
  -out configs/localhost.cert.pem \
  -days 365 \
  -subj "/C=CN/ST=BeiJing/L=BeiJing/O=GoGa/OU=Dev/CN=localhost"
```
生成后，将 `config.yaml` 中的 `tls_cert_path` 和 `tls_key_path` 指向这两个文件即可启用 HTTPS。

### 4. 运行
您可以通过以下两种方式运行本项目：

**a) HTTP 模式 (用于开发):**
确保 `tls_cert_path` 和 `tls_key_path` 在配置文件中为空。
```bash
# 设置主密钥环境变量
export GOGA_ENCRYPTION_KEY=$(openssl rand -base64 32)

# 运行
go run ./cmd/goga/main.go
# 服务将启动在 http://localhost:8080
```

**b) HTTPS 模式 (用于生产/测试):**
首先，生成证书（见上一步），然后更新您的 `config.yaml`：
```yaml
# configs/config.yaml
server:
  port: "8080"
  tls_cert_path: "configs/localhost.cert.pem"
  tls_key_path: "configs/localhost.key.pem"
# ... 其他配置
```
然后运行：
```bash
# 设置主密钥环境变量
export GOGA_ENCRYPTION_KEY=$(openssl rand -base64 32)

# 运行
go run ./cmd/goga/main.go
# 服务将启动在 https://localhost:8080
```

**c) 构建并运行二进制文件 (用于生产):**
```bash
# 构建
go build -o goga ./cmd/goga

# 设置环境变量并运行
export GOGA_ENCRYPTION_KEY=$(openssl rand -base64 32)
./goga
```

## 开发

### 项目结构
- `cmd/goga/`: 项目主程序的入口。
- `configs/`: 配置文件及加载逻辑。
- `docs/`: 项目需求、设计和任务拆解文档。
- `internal/`: 项目内部代码，不对外暴露。
  - `gateway/`: 网关的核心逻辑，包括代理、中间件等。
  - `crypto/`: 加解密相关的工具函数。
- `static/`: 存放静态文件，如 `goga-crypto.js`。
- `TASK_BREAKDOWN.md`: 详细的开发任务分解列表，新贡献者可以从此文件入手。

### 贡献



我们非常欢迎任何形式的贡献，包括代码、功能建议或文档改进！请随时提交 Pull Request 或创建 Issue。



## 开源协议



本项目采用 [GNU Affero 通用公共许可证 v3.0 (AGPL-3.0)](./LICENSE) 进行许可。



这意味着：

- 您可以自由使用、修改和分发本项目。

- 任何基于本项目修改后通过网络提供服务的软件，都必须将其完整的源代码向用户公开。

- 未经许可，不得移除代码中的版权信息。



详情请参阅项目根目录下的 [LICENSE](./LICENSE) 文件。



## Test Backend (测试后端)

`test-backend` 目录包含一个完全独立的 Go 语言模拟后端服务器。其目的是为主要的网关应用程序 (`goga`) 提供一个稳定、本地的 API 以进行测试。

### 功能

-   **模拟登录 API**: 提供一个 `/api/login` 端点，模拟用户登录功能。
-   **静态文件服务器**: 提供 `index.html` 文件，用于展示一个简单的登录界面。
-   **运行在 3000 端口**: 默认监听 `http://localhost:3000`，便于调试。

### 如何运行

要运行测试后端服务器：

```bash
cd test-backend
go build
./test-backend
```

服务器将在 `http://localhost:3000` 上可用。