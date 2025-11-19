package middleware

import (
	"log"
	"net/http"
	"time"
)

// responseWriter is a custom ResponseWriter that captures the status code
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

// Logging 是一个中间件，用于记录 HTTP 请求的信息
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// 创建自定义的 responseWriter
		rw := newResponseWriter(w)

		// 调用下一个处理器
		next.ServeHTTP(rw, r)

		duration := time.Since(start)

		// 记录日志
		        log.Printf("\"%s %s %s\" %d %s", r.Method, r.RequestURI, r.Proto, rw.statusCode, duration)	})
}
