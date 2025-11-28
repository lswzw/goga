package test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"goga/configs"
	"goga/internal/gateway"
	"goga/internal/middleware"
	"goga/internal/security"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// GoGaTestServer 封装了一个运行中的 goga 服务器，用于测试
type GoGaTestServer struct {
	URL        string
	Server     *http.Server
	BackendURL string // goga 代理到的模拟后端 URL
	Config     *configs.Config
	StopFunc   func() // 清理停止服务器的函数
	KeyCacher  security.KeyCacher
}

// StartGoGaServer 启动一个带指定配置的 goga 服务器用于测试。
// 它设置了一个最小化的 slog 日志记录器，以便在测试期间捕获日志，默认情况下不污染标准输出。
func StartGoGaServer(cfg *configs.Config) (*GoGaTestServer, error) {
	// --- START: 切换工作目录到项目根目录 ---
	// 这是为了确保相对路径 (如 "static/goga.min.js") 能被正确解析
	originalWD, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("无法获取当前工作目录: %w", err)
	}

	rootDir, err := findProjectRoot()
	if err != nil {
		return nil, fmt.Errorf("无法找到项目根目录: %w", err)
	}

	if err := os.Chdir(rootDir); err != nil {
		return nil, fmt.Errorf("无法切换到项目根目录: %w", err)
	}
	// --- END: 切换工作目录 ---

	// --- 日志和依赖项初始化 ---
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})))
	keyCacher, err := gateway.NewKeyCacherFactory(cfg.KeyCache)
	if err != nil {
		return nil, fmt.Errorf("初始化密钥缓存失败: %w", err)
	}

	// --- 处理器和路由设置 ---
	// 1. 创建 API 路由器
	apiRouter, err := gateway.NewRouter(cfg, keyCacher)
	if err != nil {
		keyCacher.Stop()
		return nil, fmt.Errorf("创建 API 路由失败: %w", err)
	}

	// 2. 创建反向代理处理器
	proxyHandler, err := gateway.NewProxy(cfg)
	if err != nil {
		keyCacher.Stop()
		return nil, fmt.Errorf("创建反向代理失败: %w", err)
	}

	// 3. 组合路由
	mainMux := http.NewServeMux()
	mainMux.Handle("/goga/", apiRouter)
	mainMux.Handle("/goga.min.js", apiRouter)
	mainMux.Handle("/", proxyHandler)

	// 4. 应用中间件
	var coreHandler http.Handler = mainMux
	if cfg.Encryption.Enabled {
		decryptionHandler := middleware.DecryptionMiddleware(keyCacher, cfg.Encryption)
		coreHandler = decryptionHandler(coreHandler)
	}

	handler := middleware.Recovery(middleware.SecurityHeadersMiddleware(middleware.Logging(middleware.HealthCheck(coreHandler))))
	
	// 5. 包裹 WebSocket 代理
	wsHandler := gateway.NewWebsocketProxy(handler, cfg)

	// --- 服务器创建和启动 ---
	// 为测试服务器使用一个随机的空闲端口
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		keyCacher.Stop()
		return nil, fmt.Errorf("查找空闲端口失败: %w", err)
	}

	server := &http.Server{
		Handler: wsHandler, // 使用最终的处理器链
		Addr:    listener.Addr().String(),
	}

	// 用于在服务器就绪时发出信号的通道
	serverReady := make(chan error, 1)

	go func() {
		slog.Info("GoGa 测试服务器启动中", "addr", server.Addr)
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			serverReady <- fmt.Errorf("goga 测试服务器失败: %w", err)
		}
		slog.Info("GoGa 测试服务器已停止", "addr", server.Addr)
		serverReady <- nil
	}()

	// 等待服务器启动或出错
	// 在实际测试中，您可能需要一个更健壮的就绪检查（例如，访问 /health 接口）
	select {
	case err := <-serverReady:
		keyCacher.Stop()
		return nil, err
	case <-time.After(200 * time.Millisecond): // 给服务器一个短暂的启动时间
		// 服务器应该已就绪，继续
	}

	// 使用 stopFunc 确保在测试结束时恢复原始工作目录
	stopFunc := func() {
		if err := os.Chdir(originalWD); err != nil {
			slog.Error("无法恢复原始工作目录", "path", originalWD, "error", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			slog.Error("关闭 goga 测试服务器失败", "error", err)
		}
		keyCacher.Stop() // 确保缓存器停止
		<-serverReady    // 等待服务器 goroutine 结束
	}

	return &GoGaTestServer{
		URL:        "http://" + server.Addr,
		Server:     server,
		BackendURL: cfg.BackendURL,
		Config:     cfg,
		StopFunc:   stopFunc,
		KeyCacher:  keyCacher,
	}, nil
}

// findProjectRoot 向上遍历目录树以查找包含 "go.mod" 文件的项目根目录。
func findProjectRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("无法在任何父目录中找到 go.mod")
		}
		dir = parent
	}
}

// MockBackendServer 封装了一个运行中的模拟后端服务器，用于测试
type MockBackendServer struct {
	URL         string
	Server      *httptest.Server
	StopFunc    func()
	LastRequest *LastRequestInfo
}

// LastRequestInfo 捕获模拟后端收到的最后一个请求的详细信息。
// 这用于测试断言。
type LastRequestInfo struct {
	sync.RWMutex
	Header http.Header
	Body   []byte
}

// StartMockBackendServer 启动一个简单的模拟后端服务器用于测试。
// 它处理 JSON 和表单编码的 /api/login 请求，并提供静态文件。
func StartMockBackendServer() *MockBackendServer {
	lastRequest := &LastRequestInfo{}
	mux := http.NewServeMux()

	// 更新登录处理程序以使用 lastRequest 对象
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		mockLoginHandler(w, r, lastRequest)
	})
	mux.HandleFunc("/some-html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, `<!DOCTYPE html><html><head><title>Test</title></head><body><h1>Hello</h1><form action="/api/login" method="POST"></form></body></html>`)
	})
	mux.HandleFunc("/other-content", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "这是一个纯文本内容。")
	})

	server := httptest.NewServer(loggingMiddleware(mux)) // 使用与 test-backend 相同的日志中间件

	return &MockBackendServer{
		URL:         server.URL,
		Server:      server,
		StopFunc:    server.Close,
		LastRequest: lastRequest,
	}
}

// mockLoginHandler 处理模拟后端的登录请求，支持 JSON 和表单编码。
func mockLoginHandler(w http.ResponseWriter, r *http.Request, lastRequest *LastRequestInfo) {
	// 记录请求详细信息
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body)) // 恢复请求体以便解析

	lastRequest.Lock()
	lastRequest.Header = r.Header.Clone()
	lastRequest.Body = body
	lastRequest.Unlock()

	if r.Method != http.MethodPost {
		http.Error(w, "不支持的方法", http.StatusMethodNotAllowed)
		return
	}

	var username, password string

	contentType := r.Header.Get("Content-Type")
	switch {
	case contentType == "application/json":
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		// 我们已经读取了请求体，所以使用新的读取器
		if err := json.NewDecoder(bytes.NewReader(body)).Decode(&req); err != nil {
			http.Error(w, "无效的 JSON 请求体", http.StatusBadRequest)
			return
		}
		username = req.Username
		password = req.Password
	case contentType == "application/x-www-form-urlencoded":
		// 使用保存的请求体解析表单数据
		r.Body = io.NopCloser(bytes.NewReader(body))
		if err := r.ParseForm(); err != nil {
			http.Error(w, "解析表单数据失败", http.StatusBadRequest)
			return
		}
		username = r.Form.Get("username")
		password = r.Form.Get("password")
	default:
		http.Error(w, "不支持的 Content-Type", http.StatusUnsupportedMediaType)
		return
	}

	// 模拟验证
	if username == "admin" && password == "password" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"token":   "fake-jwt-token-for-testing",
			"message": "登录成功",
		})
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "无效的凭据",
		})
	}
}

// loggingMiddleware 模拟后端的日志中间件 (从 test-backend/main.go 复制)
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		// 如果需要，可以在测试环境中使用 slog 进行日志记录，或者直接打印到标准错误
		// slog.Debug("模拟后端请求", "method", r.Method, "uri", r.RequestURI, "duration", time.Since(start))
		// 目前，简单的直接日志输出到标准错误即可
		fmt.Fprintf(os.Stderr, "模拟后端: %s %s %v\n", r.Method, r.RequestURI, time.Since(start))
	})
}
