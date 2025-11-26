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

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
)

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
		originalDirector(req) // 调用默认 Director，它会设置 req.URL.Scheme, req.URL.Host 等

		// 关键: 保持原始 Host 头。
		// 默认情况下，httputil.ReverseProxy 会使用目标 Host 重写 Host 头。
		// 通过不修改 req.Host，我们允许从客户端传入的原始 Host 头（例如，由 Nginx 的 proxy_set_header Host $host 设置）被保留并传递到后端。
		// 这是实现透明代理和避免重定向问题的关键。
		// req.Host = target.Host // <<-- 这一行是错误的，必须删除或注释掉

		// 其他由 Nginx 设置的头文件 (例如 X-Forwarded-For, X-Forwarded-Proto) 会被自动传递到后端，
		// 因为我们没有在这里显式地删除或修改它们。

		// --- 完善 X-Forwarded-For 逻辑 ---
		// 每个代理都应该将它所看到的客户端 IP (即上一跳的 IP) 附加到 X-Forwarded-For 链中。
		// 在 Nginx -> goga -> Backend 的结构中:
		// 1. Nginx 收到来自真实客户端的请求，将 CLIENT_IP 设置为 X-Forwarded-For。
		// 2. goga 收到来自 Nginx 的请求，goga 的 req.RemoteAddr 是 NGINX_IP。
		// 3. goga 将 NGINX_IP 附加到 X-Forwarded-For 链中，结果是 "CLIENT_IP, NGINX_IP"。
		// 这是 X-Forwarded-For 的标准行为。
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

			// 原始的响应体，在 io.ReadAll 之后，resp.Body 会被关闭。
			// 我们需要保存原始数据，以便在某些情况下原样返回。
			originalRawBody, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			if err := resp.Body.Close(); err != nil {
				return err
			}

			// 如果读取的字节数超过了限制，则放弃注入，并原样返回响应
			if len(originalRawBody) > maxBodySize {
				slog.Warn("响应体过大，跳过脚本注入", "limit_bytes", maxBodySize)
				// 直接将原始的 body 放回 resp.Body，并保持所有原始头部不变
				resp.Body = io.NopCloser(bytes.NewReader(originalRawBody))
				resp.ContentLength = int64(len(originalRawBody)) // 确保 Content-Length 正确
				// 重要的是：不修改 Content-Encoding 和 Transfer-Encoding 头
				return nil
			}

			// --- 解压与重压缩的统一逻辑 ---
			originalEncoding := resp.Header.Get("Content-Encoding")
			modifiedBody, decompressed, err := decompressBody(originalEncoding, originalRawBody)
			if err != nil {
				slog.Error("解压响应体时发生错误", "encoding", originalEncoding, "error", err)
				// 出现解压错误时，最好是返回原始响应，而不是继续处理可能已损坏的数据
				resp.Body = io.NopCloser(bytes.NewReader(originalRawBody))
				resp.ContentLength = int64(len(originalRawBody))
				// 保持原始 Content-Encoding
				return nil
			}

			// 脚本注入标志
			scriptInjected := false
			if decompressed { // 只有在成功解压的情况下才尝试注入脚本
				script := config.ScriptInjection.ScriptContent
				newBodyBytes := bytes.Replace(modifiedBody, []byte("</body>"), []byte(script+"</body>"), 1)

				if len(newBodyBytes) > len(modifiedBody) {
					slog.Debug("脚本已成功注入响应体。")
					modifiedBody = newBodyBytes
					scriptInjected = true
				} else {
					slog.Debug("未找到 `</body>` 标签，脚本注入跳过。")
				}
			}

			// --- 重新压缩逻辑 ---
			if decompressed {
				if scriptInjected {
					// 如果脚本被注入，则重新压缩修改后的 body
					modifiedBody, err = compressBody(originalEncoding, modifiedBody)
					if err != nil {
						slog.Error("重新压缩响应体时发生错误", "encoding", originalEncoding, "error", err)
						// 重新压缩失败，尝试以明文形式返回（删除编码头）
						resp.Body = io.NopCloser(bytes.NewReader(modifiedBody))
						resp.ContentLength = int64(len(modifiedBody))
						resp.Header.Del("Content-Encoding")
						return nil
					}
					slog.Info("响应体已重新压缩", "encoding", originalEncoding)
					resp.Header.Set("Content-Encoding", originalEncoding) // 确保头被设置回
				} else {
					// 脚本未注入，但响应是压缩的，恢复原始压缩体，避免不必要的解压/压缩循环
					slog.Debug("脚本未注入，恢复原始压缩响应。")
					modifiedBody = originalRawBody // 使用原始的、未解压的 body
					// 保持原始的 Content-Encoding 头
					resp.Header.Set("Content-Encoding", originalEncoding)
				}
			} else {
				// 如果原始就是明文或者解压失败，为安全起见删除此头
				resp.Header.Del("Content-Encoding")
			}

			// 更新响应体和头部
			resp.Body = io.NopCloser(bytes.NewReader(modifiedBody))
			resp.ContentLength = int64(len(modifiedBody))
			resp.Header.Del("Transfer-Encoding") // 让 http 库根据需要自动处理
		}

		return nil
	}

	return proxy, nil
}

// decompressBody 根据提供的编码类型解压 body。
func decompressBody(encoding string, body []byte) (decompressedBody []byte, decompressed bool, err error) {
	if encoding == "" {
		return body, false, nil
	}

	var reader io.Reader
	switch encoding {
	case "gzip":
		reader, err = gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, false, err
		}
	case "br":
		reader = brotli.NewReader(bytes.NewReader(body))
	case "zstd":
		reader, err = zstd.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, false, err
		}
	case "lz4":
		reader = lz4.NewReader(bytes.NewReader(body))
	default:
		// 不支持的编码，返回原始 body
		return body, false, nil
	}

	result, err := io.ReadAll(reader)
	if err != nil {
		// 如果读取失败（例如，数据损坏），返回错误
		return nil, false, err
	}

	// 对于需要 Close() 的 reader，进行关闭
	if closer, ok := reader.(io.Closer); ok {
		closer.Close()
	}

	return result, true, nil
}

// compressBody 根据提供的编码类型压缩 body。
func compressBody(encoding string, body []byte) (compressedBody []byte, err error) {
	var buf bytes.Buffer
	var writer io.WriteCloser
	switch encoding {
	case "gzip":
		writer = gzip.NewWriter(&buf)
	case "br":
		writer = brotli.NewWriter(&buf)
	case "zstd":
		writer, err = zstd.NewWriter(&buf)
		if err != nil {
			return nil, err
		}
	case "lz4":
		writer = lz4.NewWriter(&buf)
	default:
		// 不支持的编码，返回原始 body
		return body, nil
	}

	if _, err := writer.Write(body); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}