package main

import (
	"goga/configs"
	"goga/internal/gateway"
	"goga/internal/middleware"
	"log"
	"net/http"
	"time"
)

func main() {
	// 加载配置
	config, err := configs.LoadConfig()
	if err != nil {
		log.Fatalf("无法加载配置: %v", err)
	}

	// 初始化密钥缓存，每分钟清理一次
	keyCache := gateway.NewKeyCache(1 * time.Minute)
	defer keyCache.Stop() // 确保程序退出时停止后台 goroutine

	// 初始化主路由
	router, err := gateway.NewRouter(&config, keyCache)
	if err != nil {
		log.Fatalf("无法创建网关路由: %v", err)
	}

	// 创建解密中间件实例
	decryptionHandler := middleware.DecryptionMiddleware(keyCache)

	// 应用中间件
	// 顺序: Recovery -> Logging -> HealthCheck -> Decryption -> Router
	handler := middleware.Recovery(middleware.Logging(middleware.HealthCheck(decryptionHandler(router))))

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