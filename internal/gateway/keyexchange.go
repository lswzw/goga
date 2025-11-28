// Copyright (c) 2025 wangke <464829928@qq.com>
//
// This software is released under the AGPL-3.0 license.
// For more details, see the LICENSE file in the root directory.

package gateway

import (
	"encoding/json"
	"goga/internal/session"
	"log/slog"
	"net/http"

	"goga/configs"
)

// KeyExchangeRequest 表示密钥交换请求的JSON结构
type KeyExchangeRequest struct {
	ClientPublicKey string `json:"clientPublicKey"`
}

// KeyExchangeResponse 表示密钥交换响应的JSON结构
type KeyExchangeResponse struct {
	ServerPublicKey string `json:"serverPublicKey"`
	SessionID      string `json:"sessionId"`
	TTL            int    `json:"ttl"`
}

// KeyExchangeHandler 处理ECDH密钥交换请求
func KeyExchangeHandler(sessionManager *session.Manager, cfg *configs.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		// 只接受POST请求
		if req.Method != http.MethodPost {
			slog.Warn("Key exchange endpoint received non-POST request",
				"method", req.Method,
				"remote_addr", req.RemoteAddr,
			)
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// 解析请求体
		var request KeyExchangeRequest
		if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
			slog.Warn("Failed to decode key exchange request",
				"error", err,
				"remote_addr", req.RemoteAddr,
			)
			http.Error(w, "Invalid request format", http.StatusBadRequest)
			return
		}

		// 验证客户端公钥不为空
		if request.ClientPublicKey == "" {
			slog.Warn("Empty client public key in request",
				"remote_addr", req.RemoteAddr,
			)
			http.Error(w, "Client public key is required", http.StatusBadRequest)
			return
		}

		// 使用会话管理器创建会话
		session, serverPublicKey, err := sessionManager.CreateSession(request.ClientPublicKey)
		if err != nil {
			slog.Error("Failed to create ECDH session",
				"error", err,
				"remote_addr", req.RemoteAddr,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// 构建响应
		response := KeyExchangeResponse{
			ServerPublicKey: serverPublicKey,
			SessionID:      session.SessionID,
			TTL:            cfg.SessionCache.TTLSeconds,
		}

		// 设置响应头并发送JSON响应
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			slog.Error("Failed to encode key exchange response",
				"error", err,
				"remote_addr", req.RemoteAddr,
			)
		}

		slog.Debug("Key exchange completed successfully",
			"sessionID", session.SessionID,
			"remote_addr", req.RemoteAddr,
		)
	}
}

