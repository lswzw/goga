# 阶段 1: 构建应用程序
# 使用与项目版本匹配的官方 Go 镜像
FROM golang:1.24-alpine AS builder

# 在容器内设置工作目录
WORKDIR /app

# 复制 go.mod 和 go.sum 文件以利用 Docker 的层缓存机制
COPY go.mod go.sum ./
# 下载依赖
RUN go mod download

# 复制其余的源代码
COPY . .

# 构建静态链接的二进制文件，用于创建最小化的最终镜像
# -ldflags "-w -s" 参数可以去除调试信息和符号表，减小二进制文件体积
RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags "-w -s" -o /goga ./cmd/goga

# 阶段 2: 创建最终的轻量级镜像
FROM alpine:latest

# GoGa 可能需要向后端发起 HTTPS 请求，因此包含 ca-certificates 包
RUN apk --no-cache add ca-certificates

# 设置工作目录
WORKDIR /app

# 从构建器阶段复制已编译的二进制文件到当前工作目录 (/app)
COPY --from=builder /goga .

# 将配置文件和静态文件复制到工作目录下的相应子目录中
# COPY 指令会自动创建目标子目录
COPY configs/config.example.yaml ./configs/config.yaml
COPY static/goga.min.js ./static/goga.min.js

# 暴露应用程序运行的默认端口
EXPOSE 8080

# 设置容器的入口点，使用相对路径执行当前工作目录下的二进制文件
ENTRYPOINT ["./goga"]