// Copyright (c) 2025 wangke <464829928@qq.com>
//
// This software is released under the AGPL-3.0 license.
// For more details, see the LICENSE file in the root directory.

package gateway

import (
	"bytes"
	"compress/gzip"
	"goga/configs"
	"io"
	"log/slog"
	"net" // 导入 net 包
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync" // 导入 sync 包

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
)

// bufferPool 是一个用于复用字节缓冲区的 sync.Pool
var bufferPool = sync.Pool{
	New: func() interface{} {
		// 预分配一个 32KB 的缓冲区，这是一个处理中等大小 HTML 的合理起点。
		// 如果响应体更大，缓冲区会自动扩容。
		return bytes.NewBuffer(make([]byte, 0, 32*1024))
	},
}

// NewProxy 创建并返回一个配置好的反向代理处理器
func NewProxy(config *configs.Config) (http.Handler, error) {
	// 解析后端目标 URL
	target, err := url.Parse(config.BackendURL)
	if err != nil {
		slog.Error("无法解析目标 URL", "url", config.BackendURL, "error", err)
		os.Exit(1)
	}
	slog.Debug("反向代理目标已设置", "target", config.BackendURL)

	// 创建一个反向代理
	proxy := httputil.NewSingleHostReverseProxy(target)

	// 修改 Director 来自定义请求如何被转发
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req) // 调用默认 Director，它会设置一些基本头部，包括初始的 X-Forwarded-For
		req.Host = target.Host

		// --- 完善 X-Forwarded-For 逻辑 ---
		// 从 req.RemoteAddr 获取客户端 IP (不含端口)
		clientIP, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			slog.Warn("无法解析客户端 IP", "remote_addr", req.RemoteAddr, "error", err)
			clientIP = req.RemoteAddr // fallback to full remote address if parsing fails
		}

		// 获取现有的 X-Forwarded-For 头部
		existingXFF := req.Header.Get("X-Forwarded-For")

		if existingXFF == "" {
			// 如果没有 X-Forwarded-For，则直接设置
			req.Header.Set("X-Forwarded-For", clientIP)
		} else {
			// 如果已存在，则追加客户端 IP
			req.Header.Set("X-Forwarded-For", existingXFF+", "+clientIP)
		}
		// --- X-Forwarded-For 逻辑结束 ---
	}

	// 添加 ModifyResponse 函数来注入脚本
	proxy.ModifyResponse = func(resp *http.Response) error {
		const maxBodySize = 1 * 1024 * 1024
		// 1 MB: 限制 HTML 响应体最大处理尺寸。为了防止网关因处理超大 HTML 文件（例如几十 MB）而耗尽内存，同时兼顾绝大多数正常 HTML 页面（通常远小于 1MB），此值被设定为 1MB。超过此大小的 HTML 响应将不进行脚本注入。

		// 仅在加密启用、响应成功且类型为 HTML 时才注入脚本
		if config.Encryption.Enabled && resp.StatusCode == http.StatusOK && strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
			slog.Debug("响应符合脚本注入条件", "content-type", resp.Header.Get("Content-Type"), "status_code", resp.StatusCode)

			// 增加保护：限制读取大小，防止内存耗尽
			limitedReader := io.LimitReader(resp.Body, maxBodySize+1)
			body, err := io.ReadAll(limitedReader)
			if err != nil {
				return err
			}
			if err := resp.Body.Close(); err != nil {
				return err
			}

			// 如果读取的字节数超过了限制，则放弃注入
			if len(body) > maxBodySize {
				slog.Warn("响应体过大，跳过脚本注入", "limit_bytes", maxBodySize)
				resp.Body = io.NopCloser(bytes.NewReader(body))
				resp.ContentLength = int64(len(body))
				resp.Header.Del("Content-Encoding")
				return nil
			}

			// --- 解压逻辑 ---
			originalBody := body
			decompressed := false

			// 1. 检查标准的 Gzip 压缩
			if resp.Header.Get("Content-Encoding") == "gzip" {
				slog.Debug("检测到 Content-Encoding: gzip，尝试解压...")
				gz, err := gzip.NewReader(bytes.NewReader(originalBody))
				if err == nil {
					decompressedBody, err := io.ReadAll(gz)
					gz.Close()
					if err == nil {
						body = decompressedBody
						decompressed = true
						slog.Info("响应体已成功通过 Gzip 解压")
					}
				}
			}

			// 2. 如果未解压，则尝试其他算法
			if !decompressed {
				// 尝试 Zstandard
				slog.Debug("尝试 Zstandard 解压...")
				zstdReader, err := zstd.NewReader(bytes.NewReader(originalBody))
				if err == nil {
					decompressedBody, err := io.ReadAll(zstdReader)
					zstdReader.Close()
					if err == nil {
						body = decompressedBody
						decompressed = true
						slog.Info("响应体已成功通过 Zstandard 解压")
					} else {
						slog.Debug("Zstandard 读取失败", "error", err)
					}
				} else {
					slog.Debug("不是有效的 Zstandard 格式", "error", err)
				}
			}

			if !decompressed {
				// 尝试 Brotli
				slog.Debug("尝试 Brotli 解压...")
				brReader := brotli.NewReader(bytes.NewReader(originalBody))
				decompressedBody, err := io.ReadAll(brReader)
				if err == nil {
					body = decompressedBody
					decompressed = true
					slog.Info("响应体已成功通过 Brotli 解压")
				} else {
					slog.Debug("不是有效的 Brotli 格式", "error", err)
				}
			}

			if !decompressed {
				// 尝试 LZ4
				slog.Debug("尝试 LZ4 解压...")
				lz4Reader := lz4.NewReader(bytes.NewReader(originalBody))
				decompressedBody, err := io.ReadAll(lz4Reader)
				if err == nil {
					body = decompressedBody
					decompressed = true
					slog.Info("响应体已成功通过 LZ4 解压")
				} else {
					slog.Debug("不是有效的 LZ4 格式", "error", err)
				}
			}

			if !decompressed {
				slog.Warn("所有解压尝试均失败，将使用原始响应体。")
			}

			// 注入脚本
			script := config.ScriptInjection.ScriptContent
			newBodyBytes := bytes.Replace(body, []byte("</body>"), []byte(script+"</body>"), 1)

			// 检查是否发生了替换
			if len(newBodyBytes) == len(body) {
				slog.Debug("未找到 `</body>` 标签，脚本注入跳过。")
			} else {
				slog.Debug("脚本已成功注入响应体。")
			}
			body = newBodyBytes

			// 创建一个新的响应体
			newBody := io.NopCloser(bytes.NewReader(body))
			resp.Body = newBody

			// 为确保干净的状态，删除所有可能冲突的头部
			resp.Header.Del("Content-Encoding")
			resp.Header.Del("Transfer-Encoding")
			resp.Header.Del("Content-Length")

			// 设置新的、正确的 Content-Length
			resp.ContentLength = int64(len(body))
		}

		return nil
	}

	return proxy, nil
}
