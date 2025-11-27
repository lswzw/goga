// Copyright (c) 2025 wangke <464829928@qq.com>
//
// This software is released under the AGPL-3.0 license.
// For more details, see the LICENSE file in the root directory.

package gateway

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"goga/configs"
	"goga/internal/middleware"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// NewWebsocketProxy 创建一个 WebSocket 代理中间件，它会包裹现有的 http.Handler。
// 它会检查传入的请求是否为 WebSocket 升级请求。
// 如果是，它将处理代理逻辑；否则，它会将请求传递给下一个处理器。
func NewWebsocketProxy(next http.Handler, config *configs.Config) http.Handler {
	backendURL, err := url.Parse(config.BackendURL)
	if err != nil {
		slog.Error("无法解析后端 URL 用于 WebSocket 代理", "url", config.BackendURL, "error", err)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			middleware.WriteJSONError(w, r, http.StatusInternalServerError, "CONFIG_ERROR", "后端 URL 配置错误")
		})
	}

	// 预处理允许的 Origin，以便快速查找
	allowedOrigins := make(map[string]struct{})
	for _, origin := range config.Websocket.AllowedOrigins {
		allowedOrigins[strings.ToLower(origin)] = struct{}{}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isWebSocketUpgrade(r) {
			next.ServeHTTP(w, r)
			return
		}

		slog.Debug("检测到 WebSocket 升级请求，正在处理...", "url", r.URL.String())
		handleWebSocketProxy(w, r, backendURL, allowedOrigins, config)
	})
}

// isWebSocketUpgrade 检查 HTTP 请求是否为 WebSocket 升级请求。
func isWebSocketUpgrade(r *http.Request) bool {
	connHeader := strings.ToLower(r.Header.Get("Connection"))
	upgradeHeader := strings.ToLower(r.Header.Get("Upgrade"))
	return strings.Contains(connHeader, "upgrade") && upgradeHeader == "websocket"
}

// isOriginAllowed 检查请求的 Origin 是否在允许列表中。
func isOriginAllowed(r *http.Request, allowedOrigins map[string]struct{}) bool {
	if _, ok := allowedOrigins["*"]; ok {
		return true
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		// 根据规范，非浏览器客户端可能不发送 Origin。
		// 如果未配置 "*"，我们默认拒绝没有 Origin 的请求以增强安全性。
		slog.Warn("WebSocket 请求缺少 Origin 头，已拒绝", "remote_addr", r.RemoteAddr)
		return false
	}
	if _, ok := allowedOrigins[strings.ToLower(origin)]; ok {
		return true
	}
	return false
}

// handleWebSocketProxy 处理实际的 WebSocket 代理逻辑。
func handleWebSocketProxy(w http.ResponseWriter, r *http.Request, backendURL *url.URL, allowedOrigins map[string]struct{}, config *configs.Config) {
	// 0. 安全检查：验证 Origin
	if !isOriginAllowed(r, allowedOrigins) {
		middleware.WriteJSONError(w, r, http.StatusForbidden, "FORBIDDEN_ORIGIN", "请求来源不被允许")
		return
	}

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

	// 2. 使用上下文连接到后端 (支持 wss 和 context cancellation)
	var backendConn net.Conn
	var dialErr error

	// 创建一个支持上下文的拨号器
	dialer := &net.Dialer{
		Timeout:   10 * time.Second, // 总连接超时
		KeepAlive: 30 * time.Second,
	}

	if backendURL.Scheme == "https" {
		slog.Debug("正在连接到安全的 WebSocket 后端 (TLS)", "host", backendURL.Host)
		tlsConfig := &tls.Config{InsecureSkipVerify: config.Websocket.InsecureSkipVerify}
		backendConn, dialErr = tls.DialWithDialer(dialer, "tcp", backendURL.Host, tlsConfig)
	} else {
		slog.Debug("正在连接到非安全的 WebSocket 后端 (TCP)", "host", backendURL.Host)
		backendConn, dialErr = dialer.DialContext(r.Context(), "tcp", backendURL.Host)
	}

	if dialErr != nil {
		middleware.LogError(r, "无法连接到 WebSocket 后端", "host", backendURL.Host, "scheme", backendURL.Scheme, "error", dialErr)
		clientConn.Close() // Explicitly close clientConn if backend connection fails
		return
	}

	// 3. 转发客户端的握手请求到后端
	r.Host = backendURL.Host
	if err := r.Write(backendConn); err != nil {
		middleware.LogError(r, "向后端写入 WebSocket 握手请求失败", "error", err)
		backendConn.Close()
		clientConn.Close()
		return
	}

	// 4. 从后端读取响应并转发回客户端
	br := bufio.NewReader(backendConn)
	resp, err := http.ReadResponse(br, r)
	if err != nil {
		middleware.LogError(r, "从后端读取 WebSocket 握手响应失败", "error", err)
		backendConn.Close()
		clientConn.Close()
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		middleware.LogWarn(r, "WebSocket 握手失败：后端未切换协议", "status_code", resp.StatusCode)
		if err := resp.Write(clientConn); err != nil {
			middleware.LogError(r, "向客户端写入后端握手失败响应时出错", "error", err)
		}
		backendConn.Close()
		clientConn.Close()
		return
	}

	if err := resp.Write(clientConn); err != nil {
		middleware.LogError(r, "向客户端转发 WebSocket 握手响应失败", "error", err)
		backendConn.Close()
		clientConn.Close()
		return
	}
	slog.Debug("WebSocket 握手成功，开始双向数据流复制", "url", r.URL.String())

	// 5. 准备数据流并调用 transferStreams
	var backendReader io.Reader = backendConn
	if br.Buffered() > 0 {
		slog.Warn("后端连接的读缓冲区在握手后仍有数据，将使用 MultiReader", "bytes", br.Buffered(), "url", r.URL.String())
		backendReader = io.MultiReader(br, backendConn)
	}

	transferStreams(r.Context(), r.URL.String(), clientConn, backendConn, backendReader)
}

// transferStreams 在两个连接之间进行健壮的双向数据复制。
func transferStreams(ctx context.Context, requestURL string, clientConn, backendConn net.Conn, backendReader io.Reader) {
	// 确保连接在函数退出时关闭
	defer clientConn.Close()
	defer backendConn.Close()

	var wg sync.WaitGroup
	errChan := make(chan error, 2) // Channel to collect errors from goroutines
	ctxMonitorDone := make(chan struct{}) // Channel to signal context monitor goroutine to exit

	// Goroutine to close connections when context is cancelled
	go func() {
		select {
		case <-ctx.Done():
			slog.Debug("Context cancelled, closing connections", "url", requestURL)
			// Closing connections will cause io.CopyBuffer to return an error,
			// thus stopping the data transfer goroutines.
			clientConn.Close()
			backendConn.Close()
		case <-ctxMonitorDone:
			slog.Debug("Context monitor goroutine exiting cleanly", "url", requestURL)
		}
	}()

	wg.Add(2)

	// 后端 -> 客户端
	go func() {
		defer wg.Done()
		buf := getCopyBuffer()
		defer putCopyBuffer(buf)
		_, err := io.CopyBuffer(clientConn, backendReader, *buf)
		if err != nil && !isClosingError(err) {
			errChan <- err
		}
	}()

	// 客户端 -> 后端
	go func() {
		defer wg.Done()
		// 尝试进行零拷贝优化
		if tcpDst, ok := backendConn.(*net.TCPConn); ok {
			if tcpSrc, ok := clientConn.(*net.TCPConn); ok {
				slog.Debug("使用零拷贝路径进行 WebSocket 数据流复制 (客户端->后端)", "url", requestURL)
				_, err := io.Copy(tcpDst, tcpSrc) // io.Copy 在这种情况下会触发零拷贝
				if err != nil && !isClosingError(err) {
					errChan <- err
				}
				return // 零拷贝路径完成
			}
		}

		// 回退到缓冲池路径
		slog.Debug("回退到缓冲池路径进行 WebSocket 数据流复制 (客户端->后端)", "url", requestURL)
		buf := getCopyBuffer()
		defer putCopyBuffer(buf)
		_, err := io.CopyBuffer(backendConn, clientConn, *buf)
		if err != nil && !isClosingError(err) {
			errChan <- err
		}
	}()

	// 等待两个方向的复制都完成
	wg.Wait()
	close(errChan)
	close(ctxMonitorDone) // Signal context monitor to exit

	// 检查并记录所有非关闭性错误
	var copyErrors []error
	for err := range errChan {
		copyErrors = append(copyErrors, err)
	}

	if len(copyErrors) > 0 {
		slog.Warn("WebSocket 数据流复制出错", "url", requestURL, "errors", copyErrors)
	} else {
		slog.Debug("WebSocket 连接正常关闭", "url", requestURL)
	}
}

// getCopyBuffer 从池中安全地获取缓冲区。
func getCopyBuffer() *[]byte {
	if bufPtr, ok := copyBufPool.Get().(*[]byte); ok {
		return bufPtr
	}
	// 如果池中类型不匹配或为空，则创建一个新的缓冲区作为后备。
	b := make([]byte, 32*1024)
	return &b
}

// putCopyBuffer 将缓冲区安全地放回池中。
func putCopyBuffer(buf *[]byte) {
	// 重置缓冲区长度以重用内存
	*buf = (*buf)[:0]
	copyBufPool.Put(buf)
}

// isClosingError 判断一个错误是否是连接关闭时通常会发生的预期错误。
func isClosingError(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	errMsg := err.Error()
	return strings.Contains(errMsg, "use of closed network connection") ||
		strings.Contains(errMsg, "broken pipe") ||
		strings.Contains(errMsg, "connection reset by peer")
}