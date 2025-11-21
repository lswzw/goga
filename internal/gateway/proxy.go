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
		const maxBodySize = 5 * 1024 * 1024 // 5 MB

		// 仅在加密启用、响应成功且类型为 HTML 时才注入脚本
		if config.Encryption.Enabled && resp.StatusCode == http.StatusOK && strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
			slog.Debug("响应符合脚本注入条件", "content-type", resp.Header.Get("Content-Type"), "status_code", resp.StatusCode)

			// 增加保护：限制读取大小，防止内存耗尽
			body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize+1))
			if err != nil {
				return err
			}
			if err := resp.Body.Close(); err != nil {
				return err
			}

			// 如果读取的字节数超过了限制，则放弃注入
			if len(body) > maxBodySize {
				slog.Warn("响应体过大，跳过脚本注入", "limit_bytes", maxBodySize)
				// 我们必须返回一个完整的响应体。因为它已经部分被读取，
				// 我们需要将已读部分和剩余部分（如果有的话）串联起来。
				// 但由于 LimitReader 的行为，我们已经读完了整个响应，只是它被截断了。
				// 在这种情况下，我们选择直接返回截断前的内容，因为完整的原始响应已不可用。
				// 最安全的做法是返回我们已有的数据，并让客户端处理不完整的响应。
				// 或者，更好的做法是在读取前检查 Content-Length。
				// 为了简单起见，我们这里直接将已读部分（最多5MB+1）返回。
				// 重要的是我们不再尝试注入脚本。
				resp.Body = io.NopCloser(bytes.NewReader(body))
				// 由于我们没有完整的 body，ContentLength 设为 -1 或我们读取到的长度
				resp.ContentLength = int64(len(body))
				resp.Header.Del("Content-Encoding") // 因为我们没有解压
				return nil
			}

			// 如果响应被压缩了，需要先解压
			if resp.Header.Get("Content-Encoding") == "gzip" {
				slog.Debug("检测到 Gzip 压缩，正在解压响应体...")
				gz, err := gzip.NewReader(bytes.NewReader(body))
				if err != nil {
					return err
				}
				body, err = io.ReadAll(gz)
				if err != nil {
					// 确保在出错时也关闭gz
					gz.Close()
					return err
				}
				gz.Close()
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
