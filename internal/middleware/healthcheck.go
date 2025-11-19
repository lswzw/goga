package middleware

import (
	"log"
	"net"
	"net/http"
)

// HealthCheck 是一个中间件，用于处理来自本地主机的健康检查请求
func HealthCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 仅处理 /healthz 路径
		if r.URL.Path == "/healthz" {
			// 尝试解析来源地址
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				// 如果无法解析，为安全起见记录错误并拒绝访问
				log.Printf("健康检查: 无法解析来源地址 '%s': %v", r.RemoteAddr, err)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			// 检查是否为本地回环地址
			if host == "127.0.0.1" || host == "::1" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
				return
			}

			// 如果不是来自本地主机，则拒绝访问
			log.Printf("健康检查: 拒绝来自非本地主机 '%s' 的访问", host)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// 如果不是健康检查路径，则调用下一个处理器
		next.ServeHTTP(w, r)
	})
}
