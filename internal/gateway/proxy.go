// Copyright (c) 2025 wangke <464829928@qq.com>
//
// This software is released under the AGPL-3.0 license.
// For more details, see the LICENSE file in the root directory.

package gateway

import (
	"goga/configs"
	"goga/internal/middleware"
	"io"
	"log/slog"
	"net" // 导入 net 包
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
)

var copyBufPool = sync.Pool{
	New: func() interface{} {
		// 32KB 是 io.Copy 的默认缓冲区大小，一个不错的默认值。
		b := make([]byte, 32*1024)
		return &b
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

	// 设置自定义错误处理器
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		middleware.LogError(r, "反向代理错误", "error", err)

		// 检查错误的具体类型以返回更精确的状态码
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// 后端服务超时
			middleware.WriteJSONError(w, r, http.StatusGatewayTimeout, "GATEWAY_TIMEOUT", "后端服务响应超时")
		} else {
			// 其他类型的代理错误（例如，连接被拒绝）
			middleware.WriteJSONError(w, r, http.StatusBadGateway, "BAD_GATEWAY", "无法连接到后端服务")
		}
	}

	// 修改 Director 来自定义请求如何被转发
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		// 手动保留 Host 头的逻辑，以兼容无法识别 PreserveHost 的环境
		savedHost := req.Host
		originalDirector(req) // 调用默认 Director，它会设置 req.URL.Scheme, req.URL.Host 等
		req.Host = savedHost

		// --- 完善 X-Forwarded-For 逻辑 ---
		clientIP, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			middleware.LogWarn(req, "无法解析客户端 IP", "remote_addr", req.RemoteAddr, "error", err)
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
		// 1 MB: 限制 HTML 响应体最大处理尺寸。

		// 仅在加密启用、响应成功且类型为 HTML 时才注入脚本
		if config.Encryption.Enabled && resp.StatusCode == http.StatusOK && strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
			slog.Debug("响应符合脚本注入条件，将使用流式处理。", "content-type", resp.Header.Get("Content-Type"))

			encoding := resp.Header.Get("Content-Encoding")

			// 1. 移除 Content-Length 并为流式处理设置 ContentLength = -1
			resp.Header.Del("Content-Length")
			resp.ContentLength = -1

			// 2. 使用 io.LimitedReader 包装原始 body 以限制大小
			limitedReader := &io.LimitedReader{R: resp.Body, N: maxBodySize}

			var reader io.Reader = limitedReader
			var needsRecompression bool

			if encoding != "" {
				// 3. 如果有压缩，则构建流式解压 Reader
				decompressionReader, err := getDecompressionReader(encoding, limitedReader)
				if err != nil {
					slog.Error("创建流式解压 reader 失败", "encoding", encoding, "error", err)
					return nil
				}
				if decompressionReader != nil {
					reader = decompressionReader
					needsRecompression = true
					slog.Debug("已应用流式解压", "encoding", encoding)
				}
			}

			// 4. 将 reader 传递给 scriptInjector
			injector := NewScriptInjector(reader, []byte(config.ScriptInjection.ScriptContent))

			if !needsRecompression {
				// 场景一：未压缩，直接将注入器作为响应体
				resp.Body = injector
			} else {
				// 场景二：已压缩，需构建“解压->注入->重压缩”的完整管道
				pr, pw := io.Pipe()
				resp.Body = pr

				go func() {
					defer pw.Close()
					defer injector.Close() // 确保注入器也被关闭以释放其内部缓冲区

					// 创建流式压缩 writer
					compressionWriter, err := getCompressionWriter(encoding, pw)
					if err != nil {
						slog.Error("创建流式压缩 writer 失败", "encoding", encoding, "error", err)
						pw.CloseWithError(err)
						return
					}
					defer compressionWriter.Close()

					// 从池中获取缓冲区并使用 io.CopyBuffer
					bufPtr := copyBufPool.Get().(*[]byte)
					defer copyBufPool.Put(bufPtr)

					// io.CopyBuffer 将驱动整个数据流转：
					// injector (source) -> compressionWriter -> pipeWriter (sink)
					if _, err := io.CopyBuffer(compressionWriter, injector, *bufPtr); err != nil {
						// 将复制过程中发生的错误传递给管道的读取端
						pw.CloseWithError(err)
						slog.Error("在流式管道中复制数据时出错", "error", err)
					}
					slog.Debug("流式管道处理完成", "encoding", encoding)
				}()
			}
		}

		return nil
	}

	return proxy, nil
}