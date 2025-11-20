package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"
)

// Recovery 是一个中间件，用于从 panic 中恢复，防止服务器崩溃
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 使用 defer 捕获 panic
		defer func() {
			if err := recover(); err != nil {
				// 检查是否是 ReverseProxy 设计的 panic
				// 这种情况下，响应头可能已经写入
				if err == http.ErrAbortHandler {
					// 这是一个已知的、当客户端在响应写入前关闭连接时发生的情况。
					// 这不是一个服务端错误，所以我们只记录一个 Debug 级别的日志，以避免在生产环境中产生过多噪音。
					slog.Debug("客户端在响应写入前关闭连接，请求处理已中止。", "remote_addr", r.RemoteAddr, "error", err)
					return
				}

				slog.Error("捕获到未处理的 panic",
					"error", err,
					"method", r.Method,
					"uri", r.RequestURI,
					"stack", string(debug.Stack()),
				)
				// 向客户端返回一个通用的 500 错误
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}()

		// 调用下一个处理器
		next.ServeHTTP(w, r)
	})
}
