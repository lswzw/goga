package main

import (
	"goga/internal/gateway"
	"goga/internal/middleware"
	"goga/configs"
	"log"
	"net/http"
)

func main() {
	// 加载配置
	config, err := configs.LoadConfig()
	if err != nil {
		log.Fatalf("无法加载配置: %v", err)
	}

	// 初始化反向代理处理器
	proxyHandler, err := gateway.NewProxy(&config)
	if err != nil {
		log.Fatalf("无法创建反向代理: %v", err)
	}

	// 创建一个处理器来服务静态脚本文件
	staticScriptHandler := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/goga-crypto.js" {
				http.ServeFile(w, r, "static/goga-crypto.js")
				return
			}
			next.ServeHTTP(w, r)
		})
	}

	// 应用中间件
	// 顺序: Recovery -> Logging -> HealthCheck -> StaticScript -> Proxy
	handler := middleware.Recovery(middleware.Logging(middleware.HealthCheck(staticScriptHandler(proxyHandler))))

	// 创建 HTTP 服务器
	addr := ":" + config.Server.Port
	server := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	// 启动服务器
	log.Printf("GoGa Gateway 开始启动，监听于 %s", addr)
	err = server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("无法启动服务器: %v", err)
	}
}