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
			// 仅对 POST 请求和特定的 Content-Type 应用解密逻辑
			if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
				// 这个日志级别应该为 Debug，因为它在正常操作中会频繁出现
				slog.Debug("请求不符合解密条件，已跳过", "method", r.Method, "content-type", r.Header.Get("Content-Type"))
				next.ServeHTTP(w, r)
				return
			}

			// 读取请求体
			body, err := io.ReadAll(r.Body)
			if err != nil {
				slog.Error("读取请求体失败", "error", err)
				http.Error(w, "无法读取请求体", http.StatusInternalServerError)
				return
			}
			// 必须关闭原始请求体
			r.Body.Close()

			// 为了健壮性，如果后续处理失败，我们将原始请求体放回。
			r.Body = io.NopCloser(bytes.NewReader(body))

			// 尝试解析为加密载荷结构
			var payload EncryptedPayload
			if err := json.Unmarshal(body, &payload); err != nil {
				slog.Debug("请求体不是有效的加密载荷格式，已跳过解密", "error", err)
				next.ServeHTTP(w, r)
				return
			}

			// 如果解析成功，但关键字段为空，也认为它不是有效的加密请求，直接传递。
			if payload.Token == "" || payload.Encrypted == "" {
				slog.Debug("加密载荷中的 token 或 encrypted 字段为空，已跳过解密")
				next.ServeHTTP(w, r)
				return
			}

			// 从缓存中获取密钥
			key, found := keyCache.Get(payload.Token)
			if !found {
				slog.Warn("解密失败：token 无效或已过期", "token", payload.Token)
				http.Error(w, "Unauthorized: 无效或已过期的令牌", http.StatusUnauthorized)
				return
			}

			// 从 Base64 解码加密数据
			encryptedData, err := base64.StdEncoding.DecodeString(payload.Encrypted)
			if err != nil {
				slog.Warn("解密失败：无法解码 Base64 数据", "token", payload.Token, "error", err)
				http.Error(w, "Bad Request: 无效的加密数据格式", http.StatusBadRequest)
				return
			}

			// 解密数据
			decryptedData, err := crypto.DecryptAES256GCM(key, encryptedData)
			if err != nil {
				slog.Warn("解密失败：AES-GCM 解密过程出错", "token", payload.Token, "error", err)
				http.Error(w, "Bad Request: 解密失败", http.StatusBadRequest)
				return
			}

			// --- 新的二进制载荷解析逻辑 ---
			if len(decryptedData) < 1 {
				slog.Warn("解密失败：载荷过短，无法读取内容类型长度", "token", payload.Token)
				http.Error(w, "Bad Request: 无效的解密载荷", http.StatusBadRequest)
				return
			}

			// 1. 读取内容类型的长度 (第一个字节)
			contentTypeLen := int(decryptedData[0])
			bodyOffset := 1 + contentTypeLen

			if len(decryptedData) < bodyOffset {
				slog.Warn("解密失败：载荷长度不足以包含内容类型", "token", payload.Token, "expectedMinLength", bodyOffset)
				http.Error(w, "Bad Request: 载荷损坏", http.StatusBadRequest)
				return
			}

			// 2. 解析出内容类型和原始请求体
			originalContentType := string(decryptedData[1:bodyOffset])
			originalBody := decryptedData[bodyOffset:]

			// 使用解密并解析出的数据替换请求体
			r.Body = io.NopCloser(bytes.NewReader(originalBody))

			// 更新 Content-Length
			r.ContentLength = int64(len(originalBody))

			// 【关键修复】还原原始的 Content-Type
			r.Header.Set("Content-Type", originalContentType)

			slog.Debug("请求解密成功，已转发至后端服务。", "token", payload.Token, "originalContentType", originalContentType)
			next.ServeHTTP(w, r)
		})
	}
}
