# GoGa - 零侵入式 Web 表单加密网关

**GoGa** 是一个基于 Go 语言实现的高性能反向代理网关。其核心目标是在**不侵入**任何前端或后端业务系统的前提下，透明地实现对 Web 表单提交数据的应用层加密，从而增强数据在传输链路中的安全性。

---

## 核心特性

- **零侵入式代理**: 作为标准反向代理运行，无需修改现有 Web 应用的代码。
- **动态脚本注入**: 自动向 HTML 页面注入加密所需的 JavaScript 脚本。
- **客户端自动加密**: 注入的脚本自动拦截表单提交，使用 `AES-256-GCM` 算法加密数据。
- **网关透明解密**: 网关在转发前自动解密请求，后端服务无感知。
- **密钥缓存**: 支持**内存缓存**（默认）和 **Redis 缓存**（可选），以适应单机和分布式部署。
- **高度可配置**: 支持通过 YAML 文件或环境变量进行灵活配置。
- **容器化支持**: 提供 `Dockerfile` 和 `docker-compose.yml`，一键启动服务。

## 技术栈

- **后端**: Go, Gin, Viper, `log/slog`
- **前端 (注入)**: JavaScript (ES6), Web Cryptography API
- **DevOps & 工具**: Docker, Docker Compose

## 架构概览

GoGa 部署在客户端和后端业务应用之间，通过中间件链处理所有流量，实现透明的加解密。

```
Browser <--(HTTPS)--> GoGa Gateway <--> Backend Application
```
1.  浏览器请求 HTML 页面时，GoGa 在响应中**注入**加密脚本。
2.  用户提交表单时，脚本向 GoGa 请求一个**一次性加密密钥**。
3.  GoGa 生成密钥，将其缓存在**服务端（内存或 Redis）**中，然后返回给浏览器。
4.  脚本使用此密钥加密表单数据，并将加密后的数据发往 GoGa。
5.  GoGa 从缓存中取出密钥，**解密**请求，并将原始数据**转发**给后端应用。

## 快速启动 (Docker)

使用 Docker Compose 是最简单的运行方式。默认配置使用**内存缓存**，无需 Redis。

### 1. 先决条件
- [Docker](https://www.docker.com/) 和 [Docker Compose](https://docs.docker.com/compose/)

### 2. 运行
在项目根目录下，直接执行：
```bash
docker-compose up --build
```
该命令会启动 `goga` 网关和 `test-backend` 测试服务。

服务启动后，访问 `http://localhost:8080/` 即可看到测试登录页面，所有表单提交都将经过 GoGa 的透明加密处理。

需要修改端口或后端地址等配置，请直接编辑 `docker-compose.yml` 文件中的 `environment` 部分。

## 高级用法

### 使用 Redis 缓存 (可选)
如果需要部署多个 GoGa 实例，可以启用 Redis 作为共享的密钥缓存。

1.  **修改 `docker-compose.yml`**:
    -   取消 `redis` 服务的注释。
    -   在 `goga` 服务的 `environment` 部分，将 `GOGA_KEY_CACHE_TYPE` 的值改为 `redis`，并配置 Redis 地址。

2.  **重新启动**:
    ```bash
    docker-compose up --build
    ```

### 本地开发 (不使用 Docker)

默认使用内存缓存。

1.  **先决条件**:
    - Go (版本 1.22 或更高)

2.  **配置**:
    - 复制 `configs/config.example.yaml` 为 `configs/config.yaml`。默认已配置为使用内存缓存。

3.  **运行**:
    ```bash
    # 启动测试后端 (在另一个终端中)
    cd test-backend && go run . &
    cd ..
    
    # 启动 GoGa 网关
    go run ./cmd/goga/main.go
    ```

## 配置说明

配置源的优先级: **环境变量 > `config.yaml` 文件 > 默认值**。

- **环境变量**: 必须以 `GOGA_` 为前缀，用 `_` 代替 `.` (例如 `key_cache.type` -> `GOGA_KEY_CACHE_TYPE`)。
- **配置文件**: 默认路径为 `configs/config.yaml`。

**核心配置项 (`key_cache`)**:
```yaml
# configs/config.yaml
key_cache:
  # 缓存类型: "in-memory" (默认, 单机部署) 或 "redis" (分布式部署)
  type: "in-memory"
  # 密钥缓存时间 (秒)
  ttl_seconds: 300
  # 仅在 type = "redis" 时需要配置以下部分
  redis:
    addr: "localhost:6379"
    password: ""
    db: 0
```

## 贡献

欢迎任何形式的贡献！请随时提交 Pull Request 或创建 Issue。

## 开源协议

本项目采用 [AGPL-3.0](./LICENSE) 许可证。
