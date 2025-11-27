// Copyright (c) 2025 wangke <464829928@qq.com>
//
// This software is released under the AGPL-3.0 license.
// For more details, see the LICENSE file in the root directory.

package gateway

import (
	"bufio"
	"goga/configs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestConfig 创建一个用于测试的最小化配置
func newTestConfig(backendURL string) *configs.Config {
	return &configs.Config{
		BackendURL: backendURL,
		KeyCache: configs.KeyCacheConfig{
			TTLSeconds: 60,
		},
		Server: configs.ServerConfig{
			Port: "8080",
		},
	}
}

// mockWebsocketBackend 创建一个模拟的 WebSocket 后端服务器。
// 它会接受 WebSocket 升级请求，然后简单地将收到的所有数据回显（echo）回去。
func mockWebsocketBackend() *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 检查升级请求头
		if !isWebSocketUpgrade(r) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// 劫持连接
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		conn, _, err := hijacker.Hijack()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer conn.Close()

		// 发送 101 Switching Protocols 响应
		response := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n\r\n"
		conn.Write([]byte(response))

		// 简单的 echo 逻辑
		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return // 连接关闭或出错
			}
			conn.Write(buf[:n])
		}
	})
	return httptest.NewServer(handler)
}

func TestWebSocketProxy(t *testing.T) {
	// 1. 设置模拟后端
	backendServer := mockWebsocketBackend()
	defer backendServer.Close()

	// 2. 创建配置和代理
	cfg := newTestConfig(backendServer.URL)

	// 创建一个简单的 http handler 作为 next，用于测试非 websocket 请求的传递
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("next handler called"))
	})

	wsProxy := NewWebsocketProxy(nextHandler, cfg)

	// 3. 测试非 WebSocket 请求
	t.Run("Non-WebSocket request should be passed to next handler", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://localhost/some/path", nil)
		rr := httptest.NewRecorder()
		wsProxy.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code, "状态码应为 200 OK")
		assert.Equal(t, "next handler called", rr.Body.String(), "响应体应来自 next handler")
	})

	// 4. 测试 WebSocket 请求
	t.Run("WebSocket request should be proxied", func(t *testing.T) {
		// 使用 httptest.Server 运行我们的代理
		proxyServer := httptest.NewServer(wsProxy)
		defer proxyServer.Close()

		// 从服务器 URL 中获取 host
		proxyURL, err := url.Parse(proxyServer.URL)
		require.NoError(t, err)

		// 手动模拟客户端，建立一个到代理的 TCP 连接
		conn, err := net.Dial("tcp", proxyURL.Host)
		require.NoError(t, err, "连接到代理服务器不应出错")
		defer conn.Close()

		// 构造并发送一个 HTTP 升级请求
		req, err := http.NewRequest("GET", proxyServer.URL, nil)
		require.NoError(t, err)
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Host", proxyURL.Host) // 很重要，HTTP/1.1 需要 Host 头
		err = req.Write(conn)
		require.NoError(t, err)

		// 读取从代理转发过来的后端响应
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, req)
		require.NoError(t, err, "读取握手响应不应出错")
		assert.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode, "响应状态码应为 101")

		// 握手成功后，发送一条消息
		testMessage := "hello websocket"
		_, err = conn.Write([]byte(testMessage))
		require.NoError(t, err, "发送测试消息不应出错")

		// 读取回显的消息
		buf := make([]byte, 1024)
		// 设置一个超时以防测试卡住
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		require.NoError(t, err, "读取回显消息不应出错")
		assert.Equal(t, testMessage, string(buf[:n]), "收到的回显消息应与发送的相同")
	})
}


// mockHijacker 是一个实现了 http.Hijacker 接口的模拟对象，用于测试
type mockHijacker struct {
	conn      net.Conn
	header    http.Header
	wroteHeader bool
}

func (m *mockHijacker) Header() http.Header {
	if m.header == nil {
		m.header = make(http.Header)
	}
	return m.header
}

func (m *mockHijacker) Write(b []byte) (int, error) {
	if !m.wroteHeader {
		m.WriteHeader(http.StatusOK)
	}
	// 在模拟环境中，我们不关心写入的内容
	return len(b), nil
}

func (m *mockHijacker) WriteHeader(statusCode int) {
	m.wroteHeader = true
}

func (m *mockHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return m.conn, bufio.NewReadWriter(bufio.NewReader(m.conn), bufio.NewWriter(m.conn)), nil
}
