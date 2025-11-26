package middleware

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// responseWriter 是一个捕获状态码的自定义 ResponseWriter。
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	// 默认状态码为 200 OK
	return &responseWriter{w, http.StatusOK}
}

// WriteHeader 捕获状态码
func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// getClientIP 获取客户端 IP 地址。
// 它会优先检查 X-Forwarded-For 头部，如果不存在则回退到 RemoteAddr。
func getClientIP(r *http.Request) string {
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

		// 创建自定义的 responseWriter
		rw := newResponseWriter(w)

		// 调用下一个处理器
		next.ServeHTTP(rw, r)

		duration := time.Since(start)

		// 记录结构化日志
		slog.Info("http request",
			"method", r.Method,
			"uri", r.RequestURI,
			"proto", r.Proto,
			"status", rw.statusCode,
			"duration", duration,
			"client_ip", getClientIP(r),
		)
	})
}
