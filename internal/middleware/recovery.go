package middleware

import (
	"log"
	"net/http"
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
					// 这不是一个服务端错误，所以我们只返回，不记录日志，以避免日志混乱。
					return
				}

				log.Printf("panic: %+v", err)
				// 向客户端返回一个通用的 500 错误
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}()

		// 调用下一个处理器
		next.ServeHTTP(w, r)
	})
}
