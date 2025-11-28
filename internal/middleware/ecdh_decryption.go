// Copyright (c) 2025 wangke <464829928@qq.com>
//
// This software is released under the AGPL-3.0 license.
// For more details, see the LICENSE file in the root directory.

package middleware

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"goga/internal/crypto"
	"goga/internal/session"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
)

// ECDEncryptedPayload 定义了ECDH加密请求体的结构
type ECDEncryptedPayload struct {
	Version      string `json:"version"`
	SessionID    string `json:"sessionId"`
	EncryptedData string `json:"encryptedData"`
	EncryptedIV  string `json:"encryptedIV"`
	IVLength     int    `json:"ivLength"`
}

// ECDEncryptedResponse 定义了ECDH加密响应体的结构
type ECDEncryptedResponse struct {
	Version      string `json:"version"`
	SessionID    string `json:"sessionId"`
	EncryptedData string `json:"encryptedData"`
	EncryptedIV  string `json:"encryptedIV"`
	IVLength     int    `json:"ivLength"`
}

// ECDDecryptionMiddleware 创建一个用于解密传入ECDH加密请求的中间件
func ECDDecryptionMiddleware(sessionManager *session.Manager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 检查是否为加密请求的通用处理逻辑
			handlePlainTextRequest := func() {
				slog.Debug("请求为明文格式，已跳过解密，即将转发", "uri", r.RequestURI)
				next.ServeHTTP(w, r)
			}

			contentType := r.Header.Get("Content-Type")
			isJSON := strings.Contains(contentType, "application/json")

			// 解密逻辑仅对 POST 请求且 Content-Type 为 application/json 的请求应用
			if r.Method != http.MethodPost || !isJSON {
				handlePlainTextRequest()
				return
			}
			slog.Debug("开始检测请求是否为ECDH加密格式", "uri", r.RequestURI)

			// 读取请求体
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				LogError(r, "读取请求体失败", "error", err)
				WriteJSONError(w, r, http.StatusInternalServerError, "BODY_READ_FAILED", "无法读取请求体")
				return
			}
			r.Body.Close()

			// 尝试解析为ECDH加密格式
			var payload ECDEncryptedPayload
			if err := json.Unmarshal(bodyBytes, &payload); err != nil {
				// 不是ECDH加密格式，按明文处理
				slog.Debug("请求不是ECDH加密格式，按明文处理", "uri", r.RequestURI)
				r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
				r.ContentLength = int64(len(bodyBytes))
				r.Header.Set("Content-Length", strconv.Itoa(len(bodyBytes)))
				handlePlainTextRequest()
				return
			}

			// 验证ECDH加密载荷的必要字段
			if payload.Version != "1.0" || payload.SessionID == "" || payload.EncryptedData == "" || payload.EncryptedIV == "" {
				LogWarn(r, "ECDH加密载荷格式不正确")
				WriteJSONError(w, r, http.StatusBadRequest, "MALFORMED_PAYLOAD", "ECDH加密载荷格式不正确")
				return
			}

			// 从会话管理器获取会话
			session, exists := sessionManager.GetSession(payload.SessionID)
			if !exists {
				GlobalDecryptMetrics.RecordDecryptFailure("session")
				LogError(r, "安全事件：解密失败",
					"event_type", "security",
					"reason", "invalid_or_expired_session",
					"sessionId", payload.SessionID,
				)
				WriteJSONError(w, r, http.StatusUnauthorized, "INVALID_SESSION", "无效或已过期的会话")
				return
			}

			// 解码Base64数据
			encryptedData, err := crypto.DecodeBase64(payload.EncryptedData)
			if err != nil {
				GlobalDecryptMetrics.RecordDecryptFailure("decode")
				LogError(r, "解码加密数据失败", "error", err)
				WriteJSONError(w, r, http.StatusBadRequest, "DECODE_FAILED", "解码加密数据失败")
				return
			}

			encryptedIV, err := crypto.DecodeBase64(payload.EncryptedIV)
			if err != nil {
				GlobalDecryptMetrics.RecordDecryptFailure("decode")
				LogError(r, "解码加密IV失败", "error", err)
				WriteJSONError(w, r, http.StatusBadRequest, "DECODE_FAILED", "解码加密IV失败")
				return
			}

			// 解密IV
			// 注意：这里使用响应密钥解密IV，因为IV是由客户端使用请求密钥加密的
			// 而服务器使用响应密钥解密
			ivForIVDecryption := make([]byte, 12) // AES-GCM的IV长度为12字节
			if _, err := rand.Read(ivForIVDecryption); err != nil {
				GlobalDecryptMetrics.RecordDecryptFailure("iv_generation")
				LogError(r, "生成IV失败", "error", err)
				WriteJSONError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "生成IV失败")
				return
			}

		var iv []byte
		iv, err = crypto.DecryptAES256GCM(session.ResponseKey, append(ivForIVDecryption, encryptedIV...))
			if err != nil {
				GlobalDecryptMetrics.RecordDecryptFailure("iv_decrypt")
				LogError(r, "解密IV失败", "error", err)
				WriteJSONError(w, r, http.StatusBadRequest, "DECRYPTION_FAILED", "解密IV失败")
				return
			}

			// 验证解密后的IV长度
			ivLength := payload.IVLength
			if ivLength == 0 {
				ivLength = 12 // 默认长度
			}
			if len(iv) != ivLength {
				GlobalDecryptMetrics.RecordDecryptFailure("iv_length")
				LogError(r, "解密后的IV长度不匹配", "expected", ivLength, "actual", len(iv))
				WriteJSONError(w, r, http.StatusBadRequest, "DECRYPTION_FAILED", "解密后的IV长度不匹配")
				return
			}

			// 解密数据
			plaintext, err := crypto.DecryptAES256GCM(session.ResponseKey, append(iv, encryptedData...))
			if err != nil {
				GlobalDecryptMetrics.RecordDecryptFailure("data_decrypt")
				LogError(r, "解密数据失败", "error", err)
				WriteJSONError(w, r, http.StatusBadRequest, "DECRYPTION_FAILED", "解密数据失败")
				return
			}

			// 解析解密后的数据
			// 数据格式: [1字节: Content-Type长度] + [Content-Type字节] + [实际数据]
			if len(plaintext) == 0 {
				GlobalDecryptMetrics.RecordDecryptFailure("empty_data")
				LogError(r, "解密后的数据为空")
				WriteJSONError(w, r, http.StatusBadRequest, "DECRYPTION_FAILED", "解密后的数据为空")
				return
			}

			contentTypeLength := int(plaintext[0])
			if len(plaintext) < 1+contentTypeLength {
				GlobalDecryptMetrics.RecordDecryptFailure("invalid_format")
				LogError(r, "解密后的数据格式不正确")
				WriteJSONError(w, r, http.StatusBadRequest, "DECRYPTION_FAILED", "解密后的数据格式不正确")
				return
			}

			contentTypeBytes := plaintext[1 : 1+contentTypeLength]
			contentType = string(contentTypeBytes)
			if contentType == "" {
				contentType = "application/json" // 默认值
			}

			bodyData := plaintext[1+contentTypeLength:]

			// 更新请求信息
			r.Body = io.NopCloser(bytes.NewReader(bodyData))
			r.ContentLength = int64(len(bodyData))
			r.Header.Set("Content-Type", contentType)
			r.Header.Set("Content-Length", strconv.Itoa(len(bodyData)))

			// 创建响应包装器，用于加密响应
			wrapper := &responseWrapper{
				ResponseWriter: w,
				request:       r,
				session:       session,
				sessionID:     payload.SessionID,
			}

			slog.Debug("ECDH解密成功，已转发至后端服务", "sessionId", payload.SessionID, "contentType", contentType)
			next.ServeHTTP(wrapper, r)
		})
	}
}

// responseWrapper 包装http.ResponseWriter，用于加密响应
type responseWrapper struct {
	http.ResponseWriter
	request   *http.Request
	session   *session.Session
	sessionID string
	written   bool
}

// Write拦截响应写入，自动加密响应数据
func (w *responseWrapper) Write(data []byte) (int, error) {
	if w.written {
		return 0, nil // 已经写入过，忽略后续写入
	}
	w.written = true

	// 准备响应数据
	// 格式: [1字节: Content-Type长度] + [Content-Type字节] + [实际数据]
	contentType := "application/json"
	if ct := w.Header().Get("Content-Type"); ct != "" {
		contentType = ct
	}

	contentTypeBytes := []byte(contentType)
	if len(contentTypeBytes) > 255 {
		LogError(w.request, "Content-Type太长", "length", len(contentTypeBytes))
		// 直接返回未加密的响应
		_, err := w.ResponseWriter.Write(data)
		return len(data), err
	}

	// 构建响应数据
	responseData := make([]byte, 1+len(contentTypeBytes)+len(data))
	responseData[0] = byte(len(contentTypeBytes))
	copy(responseData[1:1+len(contentTypeBytes)], contentTypeBytes)
	copy(responseData[1+len(contentTypeBytes):], data)

	// 加密响应
	// 生成随机IV
	iv := make([]byte, 12) // AES-GCM的IV长度为12字节
	if _, err := rand.Read(iv); err != nil {
		LogError(w.request, "生成IV失败", "error", err)
		// 直接返回未加密的响应
		_, err := w.ResponseWriter.Write(data)
		return len(data), err
	}

	// 使用请求密钥加密数据（与解密时相反）
	encryptedData, err := crypto.EncryptAES256GCM(w.session.RequestKey, responseData)
	if err != nil {
		LogError(w.request, "加密响应数据失败", "error", err)
		// 直接返回未加密的响应
		_, err := w.ResponseWriter.Write(data)
		return len(data), err
	}

	// 加密IV
	ivForIVEncryption := make([]byte, 12)
	if _, err := rand.Read(ivForIVEncryption); err != nil {
		LogError(w.request, "生成IV加密失败", "error", err)
		// 直接返回未加密的响应
		_, err := w.ResponseWriter.Write(data)
		return len(data), err
	}

	encryptedIV, err := crypto.EncryptAES256GCM(w.session.RequestKey, append(ivForIVEncryption, iv...))
	if err != nil {
		LogError(w.request, "加密IV失败", "error", err)
		// 直接返回未加密的响应
		_, err := w.ResponseWriter.Write(data)
		return len(data), err
	}

	// 构建加密响应
	response := ECDEncryptedResponse{
		Version:      "1.0",
		SessionID:    w.sessionID,
		EncryptedData: crypto.EncodeBase64(encryptedData),
		EncryptedIV:  crypto.EncodeBase64(encryptedIV),
		IVLength:     len(iv),
	}

	// 设置响应头
	w.Header().Set("Content-Type", "application/json")

	// 序列化并发送响应
	responseBytes, err := json.Marshal(response)
	if err != nil {
		LogError(w.request, "序列化响应失败", "error", err)
		// 直接返回未加密的响应
		_, err := w.ResponseWriter.Write(data)
		return len(data), err
	}

	_, err = w.ResponseWriter.Write(responseBytes)
	if err != nil {
		LogError(w.request, "写入响应失败", "error", err)
		return 0, err
	}
	return len(responseBytes), nil
}