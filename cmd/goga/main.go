// Copyright (c) 2025 wangke <464829928@qq.com>
//
// This software is released under the AGPL-3.0 license.
// For more details, see the LICENSE file in the root directory.

package main

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"goga/configs"
	"goga/internal/gateway"
	"goga/internal/middleware"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// updateScriptContentWithSRI 为注入的脚本标签动态添加子资源完整性 (SRI) 哈希。
// 该函数在服务启动时执行一次，计算脚本文件的哈希并将其嵌入到脚本标签中。
// 这样可以确保即使服务器上的 JS 文件在运行时被篡改，客户端也会因为哈希不匹配而拒绝加载脚本。
func updateScriptContentWithSRI(scriptTag string) (string, error) {
	// 1. 从 script 标签中解析出 src 属性
	// 正则表达式匹配 <script ... src="<path>" ...>
	re := regexp.MustCompile(`src="([^"]+)"`)
	matches := re.FindStringSubmatch(scriptTag)
	if len(matches) < 2 {
		return "", fmt.Errorf("在 script_content 配置中未找到 src 属性: %s", scriptTag)
	}
	scriptURLPath := matches[1]

	// 2. 将 URL 路径映射到本地文件系统路径
	// 假设 /goga-crypto.min.js -> static/goga-crypto.min.js
	// 这种映射关系是基于 NewRouter 中静态文件服务的实现
	localPath := strings.TrimPrefix(scriptURLPath, "/")
	if !strings.HasPrefix(localPath, "static/") {
		localPath = filepath.Join("static", localPath)
	}

	// 3. 读取脚本文件内容
	fileContent, err := os.ReadFile(localPath)
	if err != nil {
		return "", fmt.Errorf("无法读取脚本文件 %s: %w", localPath, err)
	}

	// 4. 计算 SHA-384 哈希值
	hash := sha512.Sum384(fileContent)
	// 对哈希值进行 Base64 编码
	hashBase64 := base64.StdEncoding.EncodeToString(hash[:])
	sriHash := fmt.Sprintf("sha384-%s", hashBase64)

	// 5. 构建新的 script 标签
	// 找到第一个 > 的位置，将 integrity 和 crossorigin 属性插入到它前面
	insertionPoint := strings.Index(scriptTag, ">")
	if insertionPoint == -1 {
		return "", fmt.Errorf("无效的 script 标签格式: %s", scriptTag)
	}

	newTag := fmt.Sprintf(`%s integrity="%s" crossorigin="anonymous"%s`,
		scriptTag[:insertionPoint],
		sriHash,
		scriptTag[insertionPoint:],
	)

	return newTag, nil
}

func main() {
	// 加载配置
	config, err := configs.LoadConfig()
	if err != nil {
		slog.Error("无法加载配置", "error", err)
		os.Exit(1)
	}

	// 初始化分级日志系统
	var level slog.Level
	switch config.Log.LogLevel {
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

	// 根据配置设置日志输出
	var writers []io.Writer
	if len(config.Log.OutputPaths) == 0 {
		// 如果未配置任何输出，则默认输出到 stdout
		writers = append(writers, os.Stdout)
	} else {
		for _, path := range config.Log.OutputPaths {
			switch path {
			case "stdout":
				writers = append(writers, os.Stdout)
			case "stderr":
				writers = append(writers, os.Stderr)
			default:
				// 认为是文件路径
				file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
				if err != nil {
					slog.Error("无法打开日志文件", "path", path, "error", err)
					// 即使某个文件打开失败，也继续尝试其他输出
					continue
				}
				writers = append(writers, file)
				// 注意：这里没有立即 defer file.Close()，因为 logger 需要在整个应用生命周期内持有文件句柄。
				// 在一个需要优雅关闭的真实生产应用中，可能需要一个集中的资源清理机制。
			}
		}
	}

	logWriter := io.MultiWriter(writers...)

	logger := slog.New(slog.NewTextHandler(logWriter, &slog.HandlerOptions{
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

	slog.Info("日志系统初始化完成", "level", config.Log.LogLevel, "outputs", config.Log.OutputPaths)

	// 打印加载的配置信息（仅在 Debug 级别）
	// 注意：这可能会记录敏感信息（如密码），只应在受控的调试环境中使用。
	slog.Debug("加载的完整配置", "config", fmt.Sprintf("%+v", config))

	// -- START: SRI 哈希生成 --
	// 如果加密功能启用，则为注入的脚本动态生成 SRI 哈希
	if config.Encryption.Enabled {
		newScriptContent, err := updateScriptContentWithSRI(config.ScriptInjection.ScriptContent)
		if err != nil {
			slog.Error("致命错误：无法为注入脚本生成 SRI 哈希，服务将退出", "error", err)
			os.Exit(1)
		}
		// 在内存中更新配置
		config.ScriptInjection.ScriptContent = newScriptContent
		slog.Info("已成功为注入脚本生成并应用 SRI 哈希")
	}
	// -- END: SRI 哈希生成 --

	// 根据配置初始化密钥缓存 (内存或 Redis)
	keyCacher, err := gateway.NewKeyCacherFactory(config.KeyCache)
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
		decryptionHandler := middleware.DecryptionMiddleware(keyCacher, config.Encryption)
		coreHandler = decryptionHandler(coreHandler)
	} else {
		slog.Warn("加密功能已禁用，服务将作为纯反向代理运行。")
	}

	// 应用其他中间件
	// 顺序: Recovery -> SecurityHeaders -> RequestID -> Logging -> HealthCheck -> [Decryption] -> Router
	handler := middleware.Recovery(middleware.SecurityHeadersMiddleware(middleware.RequestID(middleware.Logging(middleware.HealthCheck(coreHandler)))))
	// 创建 HTTP 服务器
	addr := ":" + config.Server.Port
	server := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	// 在一个 goroutine 中启动服务器，这样它就不会阻塞主线程
	go func() {
		var startMsg string
		var err error

		if config.Server.TLSCertPath != "" && config.Server.TLSKeyPath != "" {
			startMsg = "GoGa Gateway 开始启动 (HTTPS)"
			err = server.ListenAndServeTLS(config.Server.TLSCertPath, config.Server.TLSKeyPath)
		} else {
			startMsg = "GoGa Gateway 开始启动 (HTTP)"
			err = server.ListenAndServe()
		}

		slog.Info(startMsg, "address", addr)

		// http.ErrServerClosed 是在调用 Shutdown() 后发生的正常错误，不应视为致命错误
		if err != nil && err != http.ErrServerClosed {
			slog.Error("服务器意外关闭", "error", err)
			os.Exit(1) // 如果服务器因错误而停止，则退出程序
		}
	}()

	// ---- 优雅退出逻辑 ----
	// 创建一个 channel 来接收操作系统的信号
	quit := make(chan os.Signal, 1)
	// 监听 SIGINT (Ctrl+C) 和 SIGTERM 信号
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// 阻塞主 goroutine，直到接收到一个信号
	sig := <-quit
	slog.Warn("接收到关闭信号，开始优雅退出...", "signal", sig.String())

	// 创建一个带有超时的 context，用于通知服务器在指定时间内完成现有请求
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 调用 Shutdown()，平滑地关闭服务器
	if err := server.Shutdown(ctx); err != nil {
		slog.Error("服务器优雅退出失败", "error", err)
	} else {
		slog.Info("HTTP 服务器已成功关闭。")
	}

	// 清理其他资源，例如关闭密钥缓存的后台任务或连接
	slog.Info("正在清理其余资源...")
	keyCacher.Stop()

	slog.Info("服务已成功优雅退出。")
}
