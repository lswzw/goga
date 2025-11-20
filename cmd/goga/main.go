package main

import (
	"goga/configs"
	"goga/internal/gateway"
	"goga/internal/middleware"
	"log/slog"
	"net/http"
	"os"
)

func main() {
	// 加载配置
	config, err := configs.LoadConfig()
	if err != nil {
		slog.Error("无法加载配置", "error", err)
		os.Exit(1)
	}

	// 初始化分级日志系统
	var level slog.Level
	switch config.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// 仅格式化 'time' 属性
			if a.Key == slog.TimeKey {
				return slog.String(a.Key, a.Value.Time().Format("2006-01-02 15:04:05"))
			}
			return a
		},
	}))
	slog.SetDefault(logger)

	// 根据配置初始化密钥缓存 (内存或 Redis)
	keyCacher, err := gateway.NewKeyCacherFactory(config.KeyCache, config.Encryption.KeyCacheTTLSeconds)
	if err != nil {
		slog.Error("无法初始化密钥缓存", "error", err)
		os.Exit(1)
	}
	defer keyCacher.Stop() // 确保程序退出时停止后台任务或关闭连接

	// 初始化主路由
	router, err := gateway.NewRouter(&config, keyCacher)
	if err != nil {
		slog.Error("无法创建网关路由", "error", err)
		os.Exit(1)
	}

	// 核心处理器是 router
	var coreHandler http.Handler = router

	// 根据配置，选择性地在最内层包裹解密中间件
	if config.Encryption.Enabled {
		slog.Info("加密功能已启用，应用解密中间件。")
		decryptionHandler := middleware.DecryptionMiddleware(keyCacher)
		coreHandler = decryptionHandler(coreHandler)
	} else {
		slog.Warn("加密功能已禁用，服务将作为纯反向代理运行。")
	}

	// 应用其他中间件
	// 顺序: Recovery -> Logging -> HealthCheck -> [Decryption] -> Router
	handler := middleware.Recovery(middleware.Logging(middleware.HealthCheck(coreHandler)))
	// 创建 HTTP 服务器
	addr := ":" + config.Server.Port
	server := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	// 启动服务器
	if config.Server.TLSCertPath != "" && config.Server.TLSKeyPath != "" {
		slog.Info("GoGa Gateway 开始启动 (HTTPS)", "address", addr)
		err = server.ListenAndServeTLS(config.Server.TLSCertPath, config.Server.TLSKeyPath)
	} else {
		slog.Info("GoGa Gateway 开始启动 (HTTP)", "address", addr)
		err = server.ListenAndServe()
	}

	if err != nil && err != http.ErrServerClosed {
		slog.Error("无法启动服务器", "error", err)
		os.Exit(1)
	}
}
