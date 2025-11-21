//go:build integration

package test

import (
	"goga/configs"
	"goga/internal/gateway"
	"goga/internal/middleware"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// startTestServer 是一个辅助函数，用于根据给定配置启动一个用于测试的 GoGa 服务器实例。
func startTestServer(t *testing.T, cfg *configs.Config) *httptest.Server {
	t.Helper()

	// --- 日志初始化逻辑 ---
	// 保存原始的默认 logger，以便测试后恢复
	originalLogger := slog.Default()

	var level slog.Level
	switch cfg.Log.LogLevel {
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

	var writers []io.Writer
	var logFiles []*os.File // 创建一个切片来持有所有打开的文件
	if len(cfg.Log.OutputPaths) == 0 {
		writers = append(writers, io.Discard) // 测试中若无指定，则丢弃日志
	} else {
		for _, path := range cfg.Log.OutputPaths {
			switch path {
			case "stdout":
				writers = append(writers, os.Stdout)
			case "stderr":
				writers = append(writers, os.Stderr)
			default:
				logFile, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
				if err != nil {
					t.Fatalf("测试中无法打开日志文件: %v", err)
				}
				writers = append(writers, logFile)
				logFiles = append(logFiles, logFile) // 将文件句柄加入切片以便后续关闭
			}
		}
	}
	logWriter := io.MultiWriter(writers...)

	logger := slog.New(slog.NewTextHandler(logWriter, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)
	slog.Info("日志系统初始化完成", "level", cfg.Log.LogLevel, "outputs", cfg.Log.OutputPaths)
	// --- 日志初始化结束 ---

	// 1. 初始化密钥缓存 (为测试使用内存模式)
	keyCacher, err := gateway.NewKeyCacherFactory(cfg.KeyCache)
	if err != nil {
		t.Fatalf("无法初始化密钥缓存: %v", err)
	}

	// 2. 初始化主路由
	router, err := gateway.NewRouter(cfg, keyCacher)
	if err != nil {
		t.Fatalf("无法创建网关路由: %v", err)
	}

	// 3. 组装中间件链
	var coreHandler http.Handler = router
	if cfg.Encryption.Enabled {
		decryptionHandler := middleware.DecryptionMiddleware(keyCacher)
		coreHandler = decryptionHandler(coreHandler)
	}
	handler := middleware.Recovery(middleware.SecurityHeadersMiddleware(middleware.Logging(middleware.HealthCheck(coreHandler))))

	// 4. 使用 httptest.NewServer 启动服务器
	server := httptest.NewServer(handler)

	// 5. 注册一个清理函数，在测试结束时执行
	t.Cleanup(func() {
		server.Close()
		keyCacher.Stop()
		slog.SetDefault(originalLogger) // 恢复原始 logger
		// 关闭所有打开的日志文件
		for _, logFile := range logFiles {
			logFile.Close()
		}
	})

	return server
}

// TestHealthCheckMiddleware 验证健康检查中间件是否正常工作。
func TestHealthCheckMiddleware(t *testing.T) {
	// 使用默认配置
	cfg, err := configs.LoadConfig()
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}
	// 确保后端 URL 无效，以便请求不会被成功代理，只测试中间件
	cfg.BackendURL = "http://127.0.0.1:1"

	server := startTestServer(t, &cfg)

	// 发送请求到 /healthz
	resp, err := http.Get(server.URL + "/healthz")
	if err != nil {
		t.Fatalf("发送 healthcheck 请求失败: %v", err)
	}
	defer resp.Body.Close()

	// 验证状态码
	if resp.StatusCode != http.StatusOK {
		t.Errorf("期望状态码为 %d, 实际为 %d", http.StatusOK, resp.StatusCode)
	}

	// 验证响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读取响应体失败: %v", err)
	}
	if string(body) != "OK" {
		t.Errorf("期望响应体为 'OK', 实际为 '%s'", string(body))
	}
}

// TestSecurityHeadersMiddleware 验证安全头部中间件是否正常工作。
func TestSecurityHeadersMiddleware(t *testing.T) {
	cfg, err := configs.LoadConfig()
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}
	// 确保后端 URL 无效，以便请求不会被成功代理，只测试中间件
	cfg.BackendURL = "http://127.0.0.1:1"

	server := startTestServer(t, &cfg)

	// 发送一个普通请求
	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("发送请求失败: %v", err)
	}
	defer resp.Body.Close()

	// 验证 X-Frame-Options 头部
	expectedHeader := "SAMEORIGIN"
	if header := resp.Header.Get("X-Frame-Options"); header != expectedHeader {
		t.Errorf("期望 X-Frame-Options 头部为 '%s', 实际为 '%s'", expectedHeader, header)
	}

	// 验证 X-Content-Type-Options 头部
	expectedHeader = "nosniff"
	if header := resp.Header.Get("X-Content-Type-Options"); header != expectedHeader {
		t.Errorf("期望 X-Content-Type-Options 头部为 '%s', 实际为 '%s'", expectedHeader, header)
	}
}

// TestFileLogging 验证日志是否能被正确写入到配置文件中指定的路径。
func TestFileLogging(t *testing.T) {
	// 1. 创建一个临时目录用于存放日志文件
	tempDir := t.TempDir()
	logFilePath := filepath.Join(tempDir, "test.log")

	// 2. 加载默认配置并覆盖日志输出路径
	cfg, err := configs.LoadConfig()
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}
	cfg.Log.OutputPaths = []string{logFilePath}
	cfg.BackendURL = "http://127.0.0.1:1" // 确保后端 URL 无效

	// 3. 启动服务器
	server := startTestServer(t, &cfg)

	// 4. 发送一个请求以触发日志记录
	resp, err := http.Get(server.URL + "/some-path")
	if err != nil {
		t.Fatalf("发送请求失败: %v", err)
	}
	resp.Body.Close()

	// 5. 读取日志文件内容并验证
	logContents, err := os.ReadFile(logFilePath)
	if err != nil {
		t.Fatalf("读取日志文件失败: %v", err)
	}

	logString := string(logContents)

	// 验证日志中是否包含关键信息
	if !strings.Contains(logString, "日志系统初始化完成") {
		t.Errorf("日志文件应包含 '日志系统初始化完成' 信息")
	}
	if !strings.Contains(logString, "http request") {
		t.Errorf("日志文件应包含 'http request' 信息")
	}
	if !strings.Contains(logString, "uri=/some-path") {
		t.Errorf("日志文件应包含请求的 URI '/some-path'")
	}
}
