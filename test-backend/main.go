package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

// upgrader 会将普通的 HTTP 连接升级为 WebSocket 连接。
var upgrader = websocket.Upgrader{
	// 允许所有来源的连接，这在测试环境中是安全的。
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// echoHandler 处理 WebSocket 请求。
func echoHandler(w http.ResponseWriter, r *http.Request) {
	// 将 HTTP 连接升级为 WebSocket 连接
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade connection to WebSocket: %v", err)
		return
	}
	defer conn.Close()
	log.Println("WebSocket connection established")

	// 循环读取并回显消息
	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket connection closed unexpectedly: %v", err)
			} else {
				log.Println("WebSocket connection closed normally.")
			}
			break
		}
		log.Printf("Received message: %s", message)

		// 将收到的消息写回客户端
		if err := conn.WriteMessage(messageType, message); err != nil {
			log.Printf("Failed to write message: %v", err)
			break
		}
		log.Printf("Echoed message: %s", message)
	}
}

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

	// WebSocket 路由
	mux.HandleFunc("/ws/echo", echoHandler)

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
		// 对于 WebSocket, 日志会在连接建立后立即记录，而不是在连接关闭后
		// 这对于长连接是更合适的行为
		if r.Header.Get("Upgrade") == "websocket" {
			log.Printf("%s %s %v (WebSocket Upgrade)", r.Method, r.RequestURI, time.Since(start))
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
		log.Printf("%s %s %v", r.Method, r.RequestURI, time.Since(start))
	})
}
