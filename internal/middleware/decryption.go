// Copyright (c) 2025 wangke <464829928@qq.com>
//
// This software is released under the AGPL-3.0 license.
// For more details, see the LICENSE file in the root directory.

package middleware

import (
	"bytes"
	"encoding/json"
	"goga/configs"
	"goga/internal/security"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// EncryptedPayload 定义了加密请求体的结构。
type EncryptedPayload struct {
	Token     string `json:"token"`
	Encrypted string `json:"encrypted"`
}

// DecryptionMiddleware 创建一个用于解密传入请求体的中间件。
// 使用流式处理架构，大幅减少内存分配和 GC 压力。
func DecryptionMiddleware(keyCache security.KeyCacher, cfg configs.EncryptionConfig) func(http.Handler) http.Handler {
	// 在中间件初始化时预编译正则表达式，以提高性能
	var mustEncryptRegexes []*regexp.Regexp
	for _, pattern := range cfg.MustEncryptRoutes {
		re, err := regexp.Compile(pattern)
		if err != nil {
			// 在启动时记录错误并忽略无效的正则表达式
			slog.Error("无效的强制加密路由正则表达式，已忽略", "pattern", pattern, "error", err)
			continue
		}
		mustEncryptRegexes = append(mustEncryptRegexes, re)
	}

	// isPathMandatoryEncryption 检查给定路径是否需要强制加密
	isPathMandatoryEncryption := func(path string) bool {
		for _, re := range mustEncryptRegexes {
			if re.MatchString(path) {
				return true
			}
		}
		return false
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 检查是否为普通、非加密请求的通用处理逻辑
			handlePlainTextRequest := func() {
				// 如果是强制加密的路由，但请求不是加密格式，则拒绝请求
				if isPathMandatoryEncryption(r.URL.Path) {
					slog.Error("安全事件：强制加密的路由接收到明文请求",
						"event_type", "security",
						"reason", "plaintext_request_to_sensitive_route",
						"client_ip", getClientIP(r),
						"uri", r.RequestURI,
						"method", r.Method,
					)
					WriteJSONError(w, r, http.StatusUnprocessableEntity, "ENCRYPTION_REQUIRED", "此路由要求请求必须被加密")
					return // 中断请求
				}
				// 否则，正常放行
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
			slog.Debug("开始检测请求是否加密", "uri", r.RequestURI)

			// 使用流式检测器判断是否为加密请求
			isEncrypted, peekReader, err := DetectEncryptedRequest(r.Body)
			if err != nil {
				slog.Error("检测加密请求失败", "error", err, "client_ip", getClientIP(r))
				WriteJSONError(w, r, http.StatusInternalServerError, "REQUEST_DETECTION_FAILED", "无法检测请求格式")
				return
			}
			slog.Debug("请求检测完成", "uri", r.RequestURI, "isEncrypted", isEncrypted)

			// 立即用 peekReader 替换原始 body。
			// 这确保了后续处理（无论是解密还是直接转发）都能从头读取请求体。
			r.Body = peekReader

			// 记录请求指标
			GlobalDecryptMetrics.RecordRequest(false) // 先记录为普通请求

			// 如果是加密请求，更新指标
			if isEncrypted {
				GlobalDecryptMetrics.RecordRequest(true) // 更新为加密请求
			} else {
				// 对于明文请求，完全缓冲请求体以避免竞争条件
				slog.Debug("请求为明文格式，正在缓冲请求体以确保安全转发", "uri", r.RequestURI)

				// 从 peekReader 读取整个请求体。这会获得所有权并防止与原始请求体发生竞争。
				bodyBytes, err := io.ReadAll(r.Body)
				if err != nil {
					slog.Error("读取明文请求体失败", "error", err, "client_ip", getClientIP(r))
					WriteJSONError(w, r, http.StatusInternalServerError, "BODY_READ_FAILED", "无法读取请求体")
					return
				}
				// 既然我们已经读完，就可以关闭 peekReader 了。
				r.Body.Close()

				// 从缓冲的字节创建新的请求体。
				r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
				r.ContentLength = int64(len(bodyBytes))
				r.Header.Set("Content-Length", strconv.Itoa(len(bodyBytes)))

				slog.Debug("明文请求体缓冲完毕，即将转发", "uri", r.RequestURI, "size", len(bodyBytes))

				handlePlainTextRequest()
				return
			}

			// --- 从这里开始，是处理确定为加密载荷的逻辑 ---
			// 使用流式解密器进行解密

			// 首先需要读取 JSON 头部获取 token
			// 由于 peekReader 已经预读取了部分数据，我们需要创建一个新的 reader 来完整处理
			// 这里使用一个临时方案：读取完整的 JSON 头部
			buf := GlobalBufferPool.GetMediumBuffer()
			defer func() {
				GlobalBufferPool.PutMediumBuffer(&buf)
			}()

			// 读取前 8KB 数据用于解析 JSON
			peekData, err := peekReader.Peek(8192)
			if err != nil && err != io.EOF {
				peekReader.Close()
				slog.Error("读取加密请求头部失败", "error", err, "client_ip", getClientIP(r))
				WriteJSONError(w, r, http.StatusInternalServerError, "HEADER_READ_FAILED", "无法读取请求头部")
				return
			}

			// 查找 JSON 结束位置
			jsonEnd := findJSONEnd(peekData)
			if jsonEnd == -1 {
				peekReader.Close()
				slog.Warn("无法在加密请求中找到完整的 JSON 对象", "client_ip", getClientIP(r), "uri", r.RequestURI)
				WriteJSONError(w, r, http.StatusBadRequest, "MALFORMED_PAYLOAD", "加密载荷格式错误")
				return
			}

			// 解析 JSON 获取 token
			var payload EncryptedPayload
			if err := json.Unmarshal(peekData[:jsonEnd+1], &payload); err != nil {
				peekReader.Close()
				slog.Warn("无法解析加密请求的 JSON 结构", "error", err, "client_ip", getClientIP(r), "uri", r.RequestURI)
				WriteJSONError(w, r, http.StatusBadRequest, "MALFORMED_PAYLOAD", "加密载荷格式错误")
				return
			}

			if payload.Token == "" || payload.Encrypted == "" {
				peekReader.Close()
				slog.Warn("加密请求的 JSON 缺少 'token' 或 'encrypted' 字段", "client_ip", getClientIP(r), "uri", r.RequestURI)
				WriteJSONError(w, r, http.StatusBadRequest, "INCOMPLETE_PAYLOAD", "加密载荷不完整")
				return
			}

			// 从缓存中获取密钥
			key, found := keyCache.Get(payload.Token)
			if !found {
				peekReader.Close()
				GlobalDecryptMetrics.RecordDecryptFailure("token")
				slog.Error("安全事件：解密失败",
					"event_type", "security",
					"reason", "invalid_or_expired_token",
					"client_ip", getClientIP(r),
					"uri", r.RequestURI,
					"token", payload.Token,
				)
				WriteJSONError(w, r, http.StatusUnauthorized, "INVALID_TOKEN", "无效或已过期的令牌")
				return
			}

			// 创建性能计时器
			timer := NewMetricsTimer(GlobalDecryptMetrics)

			// 获取当前内存使用情况
			allocBefore, _ := GetMemoryUsage()

			// 创建流式解密器
			decryptReader := newDecryptReader(peekReader, key)
			defer decryptReader.Close()

			// 启动解密过程，获取原始 Content-Type
			// 读取一个字节来触发解密过程
			tempBuf := make([]byte, 1)
			_, err = decryptReader.Read(tempBuf)
			if err != nil && err != io.EOF {
				GlobalDecryptMetrics.RecordDecryptFailure("decrypt")
				slog.Error("流式解密失败", "error", err, "client_ip", getClientIP(r))
				WriteJSONError(w, r, http.StatusBadRequest, "DECRYPTION_FAILED", "解密失败，数据可能已损坏或密钥不匹配")
				return
			}

			originalContentType := decryptReader.GetContentType()
			if originalContentType == "" {
				originalContentType = "application/json" // 默认值
			}

			// 计算内存使用量并停止计时
			allocAfter, _ := GetMemoryUsage()
			memoryUsed := int64(allocAfter - allocBefore)
			timer.Stop(memoryUsed)

			// 创建一个新的 reader，包含已读取的第一个字节和剩余数据
			combinedReader := io.MultiReader(
				io.LimitReader(bytes.NewReader(tempBuf), 1),
				decryptReader,
			)

			// 更新请求信息
			r.Body = io.NopCloser(combinedReader)
			// 注意：由于是流式处理，我们无法准确知道 Content-Length
			// 移除 Content-Length 头，让 HTTP 客户端使用 chunked 编码
			r.ContentLength = -1
			r.Header.Set("Content-Type", originalContentType)
			r.Header.Del("Content-Length")

			slog.Debug("流式解密成功，已转发至后端服务", "token", payload.Token, "originalContentType", originalContentType)
			next.ServeHTTP(w, r)
		})
	}
}
