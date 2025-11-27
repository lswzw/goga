// Copyright (c) 2025 wangke <464829928@qq.com>
//
// This software is released under the AGPL-3.0 license.
// For more details, see the LICENSE file in the root directory.

package gateway

import (
	"bufio"
	"crypto/tls"
	"goga/configs"
	"goga/internal/middleware"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// NewWebsocketProxy 创建一个 WebSocket 代理中间件，它会包裹现有的 http.Handler。
// 它会检查传入的请求是否为 WebSocket 升级请求。
// 如果是，它将处理代理逻辑；否则，它会将请求传递给下一个处理器。
func NewWebsocketProxy(next http.Handler, config *configs.Config) http.Handler {
	backendURL, err := url.Parse(config.BackendURL)
	if err != nil {
		slog.Error("无法解析后端 URL 用于 WebSocket 代理", "url", config.BackendURL, "error", err)
		// 返回一个处理器，该处理器对所有请求都返回内部服务器错误
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			middleware.WriteJSONError(w, r, http.StatusInternalServerError, "CONFIG_ERROR", "后端 URL 配置错误")
		})
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 检查这是否是一个 WebSocket 升级请求
		if !isWebSocketUpgrade(r) {
			// 如果不是，则调用链中的下一个处理器
			next.ServeHTTP(w, r)
			return
		}

		slog.Debug("检测到 WebSocket 升级请求，正在处理...", "url", r.URL.String())
		handleWebSocketProxy(w, r, backendURL)
	})
}

// isWebSocketUpgrade 检查 HTTP 请求是否为 WebSocket 升级请求。
func isWebSocketUpgrade(r *http.Request) bool {
	// 检查 Connection 头是否包含 "upgrade"
	connHeader := strings.ToLower(r.Header.Get("Connection"))
	isUpgrade := strings.Contains(connHeader, "upgrade")

	// 检查 Upgrade 头是否为 "websocket"
	upgradeHeader := strings.ToLower(r.Header.Get("Upgrade"))
	isWebsocket := upgradeHeader == "websocket"

	return isUpgrade && isWebsocket
}

// handleWebSocketProxy 处理实际的 WebSocket 代理逻辑。
func handleWebSocketProxy(w http.ResponseWriter, r *http.Request, backendURL *url.URL) {
	// 1. 劫持客户端连接
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		middleware.WriteJSONError(w, r, http.StatusInternalServerError, "HIJACK_NOT_SUPPORTED", "HTTP 服务器不支持连接劫持")
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		middleware.LogError(r, "无法劫持连接", "error", err)
		middleware.WriteJSONError(w, r, http.StatusInternalServerError, "HIJACK_FAILED", "无法劫持客户端连接")
		return
	}

	// 2. 连接到后端 (支持 wss)
	var backendConn net.Conn
	var dialErr error

	if backendURL.Scheme == "https" {
		// 安全的 WebSocket (wss://)
		slog.Debug("正在连接到安全的 WebSocket 后端 (TLS)", "host", backendURL.Host)
		backendConn, dialErr = tls.Dial("tcp", backendURL.Host, nil)
	} else {
		// 非安全的 WebSocket (ws://)
		slog.Debug("正在连接到非安全的 WebSocket 后端 (TCP)", "host", backendURL.Host)
		backendConn, dialErr = net.Dial("tcp", backendURL.Host)
	}

	if dialErr != nil {
		middleware.LogError(r, "无法连接到 WebSocket 后端", "host", backendURL.Host, "scheme", backendURL.Scheme, "error", dialErr)
		clientConn.Close()
		return
	}

	// 3. 转发客户端的握手请求到后端
	r.Host = backendURL.Host
	if err := r.Write(backendConn); err != nil {
		middleware.LogError(r, "向后端写入 WebSocket 握手请求失败", "error", err)
		clientConn.Close()
		backendConn.Close()
		return
	}

	// 4. 从后端读取响应并转发回客户端
	br := bufio.NewReader(backendConn)
	resp, err := http.ReadResponse(br, r)
	if err != nil {
		middleware.LogError(r, "从后端读取 WebSocket 握手响应失败", "error", err)
		clientConn.Close()
		backendConn.Close()
		return
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		middleware.LogWarn(r, "WebSocket 握手失败：后端未切换协议", "status_code", resp.StatusCode)
		if err := resp.Write(clientConn); err != nil {
			middleware.LogError(r, "向客户端写入后端握手失败响应时出错", "error", err)
		}
		clientConn.Close()
		backendConn.Close()
		return
	}

	if err := resp.Write(clientConn); err != nil {
		middleware.LogError(r, "向客户端转发 WebSocket 握手响应失败", "error", err)
		clientConn.Close()
		backendConn.Close()
		return
	}
	slog.Debug("WebSocket 握手成功，开始双向数据流复制", "url", r.URL.String())

	// 5. 准备数据流并调用 transferStreams
	var backendReader io.Reader = backendConn
	if br.Buffered() > 0 {
		slog.Warn("后端连接的读缓冲区在握手后仍有数据，将使用 MultiReader", "bytes", br.Buffered(), "url", r.URL.String())
		backendReader = io.MultiReader(br, backendConn)
	}

	transferStreams(r.URL.String(), clientConn, backendConn, backendReader)
}

// transferStreams 在两个连接之间进行双向数据复制，并在连接关闭时阻塞等待和记录日志。
// backendReader 是一个特殊的参数，它可能是一个包含了 bufio 缓存的 MultiReader。
func transferStreams(requestURL string, clientConn, backendConn net.Conn, backendReader io.Reader) {
	// transferStreams 现在负责关闭连接
	defer clientConn.Close()
	defer backendConn.Close()

	errChan := make(chan error, 2)

	// 后端 -> 客户端 的数据流
	go func() {
		// 由于 backendReader 可能不是 net.TCPConn，我们不能对这个方向进行零拷贝优化。
		// 但为了保证数据完整性，这是必要的牺牲。
		buf := copyBufPool.Get().(*[]byte)
		defer copyBufPool.Put(buf)
		_, err := io.CopyBuffer(clientConn, backendReader, *buf)
		errChan <- err
	}()

	// 客户端 -> 后端 的数据流
	go func() {
		// 这个方向仍然可以尝试零拷贝优化。
		if tcpDst, ok := backendConn.(*net.TCPConn); ok {
			if tcpSrc, ok := clientConn.(*net.TCPConn); ok {
				slog.Debug("使用零拷贝路径进行 WebSocket 数据流复制 (客户端->后端)", "url", requestURL)
				_, err := io.Copy(tcpDst, tcpSrc)
				errChan <- err
				return
			}
		}

		// 回退到缓冲池路径
		slog.Debug("回退到缓冲池路径进行 WebSocket 数据流复制 (客户端->后端)", "url", requestURL)
		buf := copyBufPool.Get().(*[]byte)
		defer copyBufPool.Put(buf)
		_, err := io.CopyBuffer(backendConn, clientConn, *buf)
		errChan <- err
	}()


	// 等待第一个 goroutine 完成 (或出错)
	err := <-errChan
	if !isClosingError(err) {
		slog.Warn("WebSocket 数据流复制错误", "url", requestURL, "error", err)
	} else {
		slog.Debug("WebSocket 连接正常关闭", "url", requestURL)
	}
	
	// 通过 defer 语句确保连接被关闭。另一个 goroutine 在连接关闭后也会很快退出。
}

// isClosingError 判断一个错误是否是连接关闭时通常会发生的预期错误。
func isClosingError(err error) bool {
	if err == nil || err == io.EOF {
		return true
	}
	// 检查错误信息字符串，因为底层的错误类型可能因操作系统而异。
	errMsg := err.Error()
	if strings.Contains(errMsg, "use of closed network connection") ||
		strings.Contains(errMsg, "broken pipe") ||
		strings.Contains(errMsg, "connection reset by peer") {
		return true
	}
	return false
}