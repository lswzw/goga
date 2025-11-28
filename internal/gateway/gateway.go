// Copyright (c) 2025 wangke <464829928@qq.com>
//
// This software is released under the AGPL-3.0 license.
// For more details, see the LICENSE file in the root directory.

package gateway

import (
	"goga/configs"
	"goga/internal/security"
	"goga/internal/session"
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
func NewRouter(cfg *configs.Config, kc security.KeyCacher, sm *session.Manager) (http.Handler, error) {
	mux := http.NewServeMux()
	r := &Router{
		mux:         mux,
		keyCache:    kc,
		keyCacheTTL: time.Duration(cfg.KeyCache.TTLSeconds) * time.Second,
	}

	// 注册 ECDH 密钥交换处理器
	slog.Debug("注册 ECDH 密钥交换处理器", "path", "/goga/api/v1/key-exchange")
	mux.HandleFunc("/goga/api/v1/key-exchange", KeyExchangeHandler(sm, cfg))

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



// staticScriptHandler 用于提供 goga.js 文件。
func (r *Router) staticScriptHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		slog.Debug("正在提供静态加密脚本", "path", "static/goga.min.js")
		http.ServeFile(w, req, "static/goga.min.js")
	}
}
