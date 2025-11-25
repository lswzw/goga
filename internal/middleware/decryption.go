// Copyright (c) 2025 wangke <464829928@qq.com>
//
// This software is released under the AGPL-3.0 license.
// For more details, see the LICENSE file in the root directory.

package middleware

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"goga/internal/crypto"
	"goga/internal/gateway"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

// EncryptedPayload 定义了加密请求体的结构。
type EncryptedPayload struct {
	Token     string `json:"token"`
	Encrypted string `json:"encrypted"`
}

// DecryptionMiddleware 创建一个用于解密传入请求体的中间件。
func DecryptionMiddleware(keyCache gateway.KeyCacher) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			contentType := r.Header.Get("Content-Type")
			isJSON := strings.Contains(contentType, "application/json")
			isForm := strings.Contains(contentType, "application/x-www-form-urlencoded")

			// 仅对 POST 请求且 Content-Type 为 json 或 form-urlencoded 的请求应用解密逻辑
			if r.Method != http.MethodPost || (!isJSON && !isForm) {
				slog.Debug("请求不符合解密条件，已跳过", "method", r.Method, "content-type", contentType)
				next.ServeHTTP(w, r)
				return
			}

			// 读取请求体
			body, err := io.ReadAll(r.Body)
			if err != nil {
				slog.Error("读取请求体失败", "error", err, "client_ip", getClientIP(r))
				http.Error(w, "无法读取请求体", http.StatusInternalServerError)
				return
			}
			r.Body.Close()

			// 为了健壮性，如果后续处理失败，我们将原始请求体放回。
			r.Body = io.NopCloser(bytes.NewReader(body))

			// 如果请求体为空，则不可能是有效的加密载荷，直接跳过。
			if len(body) == 0 {
				slog.Debug("请求体为空，已跳过解密")
				next.ServeHTTP(w, r)
				return
			}

			// 尝试解析为加密载荷结构
			var payload EncryptedPayload
			if err := json.Unmarshal(body, &payload); err != nil {
				slog.Debug("请求体不是有效的加密载荷格式，已跳过解密", "error", err)
				next.ServeHTTP(w, r)
				return
			}

			if payload.Token == "" || payload.Encrypted == "" {
				slog.Debug("加密载荷中的 token 或 encrypted 字段为空，已跳过解密")
				next.ServeHTTP(w, r)
				return
			}

			// 从缓存中获取密钥
			key, found := keyCache.Get(payload.Token)
			if !found {
				slog.Error("安全事件：解密失败",
					"event_type", "security",
					"reason", "invalid_or_expired_token",
					"client_ip", getClientIP(r),
					"uri", r.RequestURI,
					"token", payload.Token,
				)
				http.Error(w, "Unauthorized: 无效或已过期的令牌", http.StatusUnauthorized)
				return
			}

			// 从 Base64 解码加密数据
			encryptedData, err := base64.StdEncoding.DecodeString(payload.Encrypted)
			if err != nil {
				slog.Error("安全事件：解密失败",
					"event_type", "security",
					"reason", "base64_decode_error",
					"client_ip", getClientIP(r),
					"uri", r.RequestURI,
					"token", payload.Token,
					"error", err.Error(),
				)
				http.Error(w, "Bad Request: 无效的加密数据格式", http.StatusBadRequest)
				return
			}

			// 解密数据
			decryptedData, err := crypto.DecryptAES256GCM(key, encryptedData)
			if err != nil {
				slog.Error("安全事件：解密失败",
					"event_type", "security",
					"reason", "decryption_error",
					"client_ip", getClientIP(r),
					"uri", r.RequestURI,
					"token", payload.Token,
					"error", err.Error(),
				)
				http.Error(w, "Bad Request: 解密失败", http.StatusBadRequest)
				return
			}

			// --- 新的二进制载荷解析逻辑 ---
			if len(decryptedData) < 1 {
				slog.Error("安全事件：解密失败",
					"event_type", "security",
					"reason", "payload_too_short",
					"client_ip", getClientIP(r),
					"uri", r.RequestURI,
					"token", payload.Token,
				)
				http.Error(w, "Bad Request: 无效的解密载荷", http.StatusBadRequest)
				return
			}

			contentTypeLen := int(decryptedData[0])
			bodyOffset := 1 + contentTypeLen

			if len(decryptedData) < bodyOffset {
				slog.Error("安全事件：解密失败",
					"event_type", "security",
					"reason", "payload_corrupted",
					"client_ip", getClientIP(r),
					"uri", r.RequestURI,
					"token", payload.Token,
					"expected_min_length", bodyOffset,
					"actual_length", len(decryptedData),
				)
				http.Error(w, "Bad Request: 载荷损坏", http.StatusBadRequest)
				return
			}

			originalContentType := string(decryptedData[1:bodyOffset])
			originalBody := decryptedData[bodyOffset:]

			// 添加解密内容调试日志
			slog.Debug("解密后的原始请求体", "body", string(originalBody))

			r.Body = io.NopCloser(bytes.NewReader(originalBody))
			r.ContentLength = int64(len(originalBody))
			r.Header.Set("Content-Type", originalContentType)

			slog.Debug("请求解密成功，已转发至后端服务。", "token", payload.Token, "originalContentType", originalContentType)
			next.ServeHTTP(w, r)
		})
	}
}
