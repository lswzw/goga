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
				log.Printf("panic: %+v", err)
				// 向客户端返回一个通用的 500 错误
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}()

		// 调用下一个处理器
		next.ServeHTTP(w, r)
	})
}
