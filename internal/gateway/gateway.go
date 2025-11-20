package gateway

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"goga/configs"
	"log/slog"
	"net/http"
	"time"
)

// Router 封装了网关的路由逻辑和依赖项。
type Router struct {
	mux      *http.ServeMux
	keyCache *KeyCache
}

// NewRouter 创建一个新的路由器，配置所有路由，并将其作为 http.Handler 返回。
func NewRouter(cfg *configs.Config, kc *KeyCache) (http.Handler, error) {
	mux := http.NewServeMux()
	r := &Router{
		mux:      mux,
		keyCache: kc,
	}

	// 创建反向代理处理器
	proxyHandler, err := NewProxy(cfg)
	if err != nil {
		return nil, err
	}

	// 注册所有处理器
	slog.Debug("注册 API 处理器", "path", "/goga/api/v1/key")
	mux.HandleFunc("/goga/api/v1/key", r.keyDistributionHandler())

	slog.Debug("注册静态脚本处理器", "path", "/goga-crypto.min.js")
	mux.HandleFunc("/goga-crypto.min.js", r.staticScriptHandler())

	slog.Debug("注册默认反向代理处理器", "path", "/")
	mux.Handle("/", proxyHandler) // 默认捕获所有其他请求

	return r, nil
}

// ServeHTTP 使 Router 实现 http.Handler 接口。
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}

// keyDistributionHandler 处理一次性加密密钥的生成和分发。
func (r *Router) keyDistributionHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			slog.Warn("密钥分发端点收到非 GET 请求", "method", req.Method, "remote_addr", req.RemoteAddr)
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		// 1. 生成一个 32 字节的随机密钥 (用于 AES-256)
		onetimeKey := make([]byte, 32)
		if _, err := rand.Read(onetimeKey); err != nil {
			slog.Error("生成一次性密钥失败", "error", err)
			http.Error(w, "Failed to generate key", http.StatusInternalServerError)
			return
		}

		// 2. 生成一个 32 字节的随机令牌
		tokenBytes := make([]byte, 32)
		if _, err := rand.Read(tokenBytes); err != nil {
			slog.Error("生成令牌失败", "error", err)
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}
		// 将令牌编码为字符串格式，适合用作 map 键和在 JSON 中使用
		token := base64.URLEncoding.EncodeToString(tokenBytes)

		// 3. 将密钥以令牌为键存入缓存
		r.keyCache.Set(token, onetimeKey, 5*time.Minute)
		slog.Debug("生成并缓存了一次性密钥", "token", token)

		// 4. 构建并发送 JSON 响应
		response := struct {
			Key   string `json:"key"`
			Token string `json:"token"`
		}{
			Key:   base64.StdEncoding.EncodeToString(onetimeKey),
			Token: token,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}
}

// staticScriptHandler 用于提供 goga-crypto.js 文件。
func (r *Router) staticScriptHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		slog.Debug("正在提供静态加密脚本", "path", "static/goga-crypto.min.js")
		http.ServeFile(w, req, "static/goga-crypto.min.js")
	}
}
