package middleware

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"goga/internal/crypto"
	"goga/internal/gateway"
	"io"
	"log"
	"net/http"
)

// EncryptedPayload 定义了加密请求体的结构。
type EncryptedPayload struct {
	Token     string `json:"token"`
	Encrypted string `json:"encrypted"`
}

// DecryptionMiddleware 创建一个用于解密传入请求体的中间件。
func DecryptionMiddleware(keyCache *gateway.KeyCache) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 仅对 POST 请求和特定的 Content-Type 应用解密逻辑
			if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
				next.ServeHTTP(w, r)
				return
			}

			// 读取请求体
			body, err := io.ReadAll(r.Body)
			if err != nil {
				log.Printf("错误: 读取请求体失败: %v", err)
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
				// 如果解析失败，说明它不是我们期望的加密格式，直接传递给下一个处理器。
				next.ServeHTTP(w, r)
				return
			}

			// 如果解析成功，但关键字段为空，也认为它不是有效的加密请求，直接传递。
			if payload.Token == "" || payload.Encrypted == "" {
				next.ServeHTTP(w, r)
				return
			}

			// 从缓存中获取密钥
			key, found := keyCache.Get(payload.Token)
			if !found {
				http.Error(w, "Unauthorized: 无效或已过期的令牌", http.StatusUnauthorized)
				return
			}
			
			// 从 Base64 解码加密数据
			encryptedData, err := base64.StdEncoding.DecodeString(payload.Encrypted)
			if err != nil {
				http.Error(w, "Bad Request: 无效的加密数据格式", http.StatusBadRequest)
				return
			}

			// 解密数据
			decryptedData, err := crypto.DecryptAES256GCM(key, encryptedData)
			if err != nil {
				// 解密失败通常意味着数据被篡改或密钥错误
				http.Error(w, "Bad Request: 解密失败", http.StatusBadRequest)
				return
			}

			// 用解密后的数据替换请求体
			r.Body = io.NopCloser(bytes.NewReader(decryptedData))
			// 更新 Content-Length
			r.ContentLength = int64(len(decryptedData))
			// 假设解密后的数据是表单序列化后的 JSON
			r.Header.Set("Content-Type", "application/json")

			log.Println("请求解密成功，已转发至后端服务。")
			next.ServeHTTP(w, r)
		})
	}
}
