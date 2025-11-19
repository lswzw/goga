
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// LoginRequest 定义了登录请求的 JSON 结构
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse 定义了登录成功响应的 JSON 结构
type LoginResponse struct {
	Token   string `json:"token"`
	Message string `json:"message"`
}

// loginHandler 处理登录请求
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Unsupported method", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 模拟验证逻辑
	if req.Username == "admin" && req.Password == "password" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(LoginResponse{
			Token:   "fake-jwt-token-for-testing",
			Message: "Login successful",
		})
	} else {
		http.Error(w, `{"message": "Invalid credentials"}`, http.StatusUnauthorized)
	}
}

func main() {
	// 创建一个新的 HTTP ServeMux
	mux := http.NewServeMux()

	// API 路由
	mux.HandleFunc("/api/login", loginHandler)

	// 静态文件服务
	// http.Dir(".") 表示使用当前目录作为根目录
	// http.StripPrefix("/", ...) 是为了确保能正确找到文件
	fs := http.FileServer(http.Dir("."))
	mux.Handle("/", fs)

	// 应用日志中间件
	loggedMux := loggingMiddleware(mux)

	// 创建并配置服务器
	server := &http.Server{
		Addr:         ":3000",
		Handler:      loggedMux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Println("Test backend server starting on :3000")
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

// loggingMiddleware 记录所有请求的信息
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %v", r.Method, r.RequestURI, time.Since(start))
	})
}
