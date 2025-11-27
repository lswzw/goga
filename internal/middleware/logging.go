package middleware

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// requestBodyCounter 是一个包装了 io.ReadCloser 的装饰器，用于计算读取的字节数。
type requestBodyCounter struct {
	io.ReadCloser
	bytesRead int64
}

// Read 包装了底层的 Read 方法，并累加读取的字节数。
func (rbc *requestBodyCounter) Read(p []byte) (int, error) {
	n, err := rbc.ReadCloser.Read(p)
	rbc.bytesRead += int64(n)
	return n, err
}

// responseWriter 是一个捕获状态码并记录写入字节数的自定义 ResponseWriter。
type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	// 默认状态码为 200 OK
	return &responseWriter{w, http.StatusOK, 0}
}

// WriteHeader 捕获状态码
func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Write 包装了原始的 Write 方法，并累加写入的字节数。
func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += n
	return n, err
}

// GetClientIP 获取客户端 IP 地址。
// 它会优先检查 X-Forwarded-For 头部，如果不存在则回退到 RemoteAddr。
func GetClientIP(r *http.Request) string {
	// 检查 X-Forwarded-For 头部，通常由代理服务器设置
	forwardedFor := r.Header.Get("X-Forwarded-For")
	if forwardedFor != "" {
		// X-Forwarded-For 可能包含多个 IP 地址，通常第一个是真实的客户端 IP
		ips := strings.Split(forwardedFor, ",")
		return strings.TrimSpace(ips[0])
	}

	// 如果没有 X-Forwarded-For，则使用 RemoteAddr
	// RemoteAddr 的格式可能是 "ip:port"，我们需要分离出 IP
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// 如果解析失败（例如没有端口），则假定 RemoteAddr 就是 IP
		return r.RemoteAddr
	}
	return ip
}

// Logging 是一个中间件，用于记录 HTTP 请求的信息
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// 创建用于统计响应大小和状态的 writer
		rw := newResponseWriter(w)

		// 创建用于统计请求大小的 body 读取器
		bodyCounter := &requestBodyCounter{ReadCloser: r.Body}
		r.Body = bodyCounter

		// 调用下一个处理器
		next.ServeHTTP(rw, r)

		duration := time.Since(start)

		// 从 context 中获取 requestID
		requestID, _ := r.Context().Value(RequestIDKey).(string)

		// 记录结构化日志
		slog.Info(
			"goga request",
			"trace_id", requestID,
			"host", r.Host,
			"method", r.Method,
			"uri", r.RequestURI,
			"proto", r.Proto,
			"status", rw.statusCode,
			"duration", duration,
			"client_ip", GetClientIP(r),
			"request_size", bodyCounter.bytesRead, // 使用实际读取的字节数
			"response_size", rw.bytesWritten,
			"user_agent", r.UserAgent(),
		)
	})
}
