// Copyright (c) 2025 wangke <464829928@qq.com>
//
// This software is released under the AGPL-3.0 license.
// For more details, see the LICENSE file in the root directory.

package gateway

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"goga/configs"
	"goga/internal/middleware"
	"goga/internal/security"
	"log/slog"
	"net/http"
	"time"
)

// Router 封装了网关的路由逻辑和依赖项。
type Router struct {
	mux         *http.ServeMux
	keyCache    security.KeyCacher
	keyCacheTTL time.Duration
}

// NewRouter 创建并返回一个只包含 API 和静态文件路由的 http.ServeMux。
// 它不再处理反向代理的逻辑。
func NewRouter(cfg *configs.Config, kc security.KeyCacher) (http.Handler, error) {
	mux := http.NewServeMux()
	r := &Router{
		mux:         mux,
		keyCache:    kc,
		keyCacheTTL: time.Duration(cfg.KeyCache.TTLSeconds) * time.Second,
	}

	// 注册 API 处理器
	slog.Debug("注册 API 处理器", "path", "/goga/api/v1/key")
	mux.HandleFunc("/goga/api/v1/key", r.keyDistributionHandler(cfg))

	// 注册静态脚本处理器
	// 注意：这里的路径是 "/goga.min.js"，在 main.go 中需要确保它被正确代理
	slog.Debug("注册静态脚本处理器", "path", "/goga.min.js")
	mux.HandleFunc("/goga.min.js", r.staticScriptHandler())

	return r, nil
}

// ServeHTTP 使 Router 实现 http.Handler 接口。
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}

// keyDistributionHandler 处理一次性加密密钥的生成和分发。
func (r *Router) keyDistributionHandler(cfg *configs.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			middleware.LogWarn(req, "密钥分发端点收到非 GET 请求", "event_type", "security")
			middleware.WriteJSONError(w, req, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "此端点仅支持 GET 方法")
			return
		}

		// 1. 生成一个 32 字节的随机密钥 (用于 AES-256)
		onetimeKey := make([]byte, 32)
		if _, err := rand.Read(onetimeKey); err != nil {
			middleware.LogError(req, "生成一次性密钥失败", "error", err)
			middleware.WriteJSONError(w, req, http.StatusInternalServerError, "KEY_GENERATION_FAILED", "生成密钥失败")
			return
		}

		// 2. 生成一个 32 字节的随机令牌
		tokenBytes := make([]byte, 32)
		if _, err := rand.Read(tokenBytes); err != nil {
			middleware.LogError(req, "生成令牌失败", "error", err)
			middleware.WriteJSONError(w, req, http.StatusInternalServerError, "TOKEN_GENERATION_FAILED", "生成令牌失败")
			return
		}
		// 将令牌编码为字符串格式，适合用作 map 键和在 JSON 中使用
		token := base64.URLEncoding.EncodeToString(tokenBytes)

		// 3. 将密钥以令牌为键存入缓存
		r.keyCache.Set(token, onetimeKey, r.keyCacheTTL)
		slog.Debug("生成并缓存了一次性密钥", "token", token)

		// 4. 构建并发送 JSON 响应
		response := struct {
			Key   string `json:"key"`
			Token string `json:"token"`
			TTL   int    `json:"ttl"`
		}{
			Key:   base64.StdEncoding.EncodeToString(onetimeKey),
			Token: token,
			TTL:   cfg.KeyCache.TTLSeconds,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}
}

// staticScriptHandler 用于提供 goga.js 文件。
func (r *Router) staticScriptHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		slog.Debug("正在提供静态加密脚本", "path", "static/goga.min.js")
		http.ServeFile(w, req, "static/goga.min.js")
	}
}
