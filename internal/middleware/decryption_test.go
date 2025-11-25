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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"goga/configs"
)

// mockKeyCacher 是一个用于测试的 KeyCacher 伪实现。
type mockKeyCacher struct {
	key []byte
}

func newMockKeyCacher() (gateway.KeyCacher, []byte) {
	// 使用一个固定的、有效的 32 字节密钥用于可重复的测试。
	key := []byte("0123456789abcdef0123456789abcdef")
	return &mockKeyCacher{key: key}, key
}

func (m *mockKeyCacher) Set(token string, key []byte, ttl time.Duration) {}
func (m *mockKeyCacher) Get(token string) ([]byte, bool) {
	if token == "test_token" {
		return m.key, true
	}
	return nil, false
}
func (m *mockKeyCacher) Stop() {}

// TestDecryptionMiddleware 是解密中间件的表驱动测试。
func TestDecryptionMiddleware(t *testing.T) {
	// 1. 设置测试环境
	mockCache, testKey := newMockKeyCacher()
	middleware := DecryptionMiddleware(mockCache, configs.EncryptionConfig{})

	// 2. 定义测试用例
	testCases := []struct {
		name                   string
		method                 string
		requestContentType     string
		requestBody            func() io.Reader // 使用函数生成请求体，以确保每次测试都能读取
		expectedStatusCode     int
		expectedResponseBody   string // 解密后期望在下一层 handler 中读到的 body
		expectedResponseHeader string // 解密后期望在下一层 handler 中读到的 Content-Type
	}{
		{
			name:               "成功的解密 (form-urlencoded 加密请求)",
			method:             "POST",
			requestContentType: "application/json",
			requestBody: func() io.Reader {
				// 准备原始数据
				originalBody := []byte("field1=value1&field2=value2")
				originalContentType := "application/x-www-form-urlencoded"

				// 构造二进制载荷
				payload := []byte{byte(len(originalContentType))}
				payload = append(payload, []byte(originalContentType)...)
				payload = append(payload, originalBody...)

				// 加密
				encrypted, _ := crypto.EncryptAES256GCM(testKey, payload)
				encryptedBase64 := base64.StdEncoding.EncodeToString(encrypted)

				// 构造最终请求体
				finalPayload := EncryptedPayload{
					Token:     "test_token",
					Encrypted: encryptedBase64,
				}
				bodyBytes, _ := json.Marshal(finalPayload)
				return bytes.NewReader(bodyBytes)
			},
			expectedStatusCode:     http.StatusOK,
			expectedResponseBody:   "field1=value1&field2=value2",
			expectedResponseHeader: "application/x-www-form-urlencoded",
		},
		{
			name:               "成功的解密 (json)",
			method:             "POST",
			requestContentType: "application/json",
			requestBody: func() io.Reader {
				originalBody := []byte(`{"key":"value"}`)
				originalContentType := "application/json; charset=utf-8"

				payload := []byte{byte(len(originalContentType))}
				payload = append(payload, []byte(originalContentType)...)
				payload = append(payload, originalBody...)

				encrypted, _ := crypto.EncryptAES256GCM(testKey, payload)
				encryptedBase64 := base64.StdEncoding.EncodeToString(encrypted)

				finalPayload := EncryptedPayload{
					Token:     "test_token",
					Encrypted: encryptedBase64,
				}
				bodyBytes, _ := json.Marshal(finalPayload)
				return bytes.NewReader(bodyBytes)
			},
			expectedStatusCode:     http.StatusOK,
			expectedResponseBody:   `{"key":"value"}`,
			expectedResponseHeader: "application/json; charset=utf-8",
		},
		{
			name:               "跳过解密 (GET请求)",
			method:             "GET",
			requestContentType: "",
			requestBody: func() io.Reader {
				return nil
			},
			expectedStatusCode:   http.StatusOK,
			expectedResponseBody: "",
		},
		{
			name:               "跳过解密 (不相关的POST请求)",
			method:             "POST",
			requestContentType: "text/plain",
			requestBody: func() io.Reader {
				return strings.NewReader("just plain text")
			},
			expectedStatusCode:   http.StatusOK,
			expectedResponseBody: "just plain text", // 中间件应直接透传
		},
		{
			name:               "跳过解密 (空body的POST请求)",
			method:             "POST",
			requestContentType: "application/x-www-form-urlencoded",
			requestBody: func() io.Reader {
				return bytes.NewReader([]byte{})
			},
			expectedStatusCode:   http.StatusOK,
			expectedResponseBody: "",
		},
		{
			name:               "解密失败 (无效token)",
			method:             "POST",
			requestContentType: "application/json",
			requestBody: func() io.Reader {
				finalPayload := EncryptedPayload{
					Token:     "invalid_token",
					Encrypted: "some_data",
				}
				bodyBytes, _ := json.Marshal(finalPayload)
				return bytes.NewReader(bodyBytes)
			},
			expectedStatusCode:   http.StatusUnauthorized,
			expectedResponseBody: "", // 错误场景下，body 不会被传递
		},
		{
			name:               "跳过解密 (form-urlencoded 明文请求)",
			method:             "POST",
			requestContentType: "application/x-www-form-urlencoded; charset=UTF-8",
			requestBody: func() io.Reader {
				return strings.NewReader("field1=value1&field2=value2")
			},
			expectedStatusCode:     http.StatusOK,
			expectedResponseBody:   "field1=value1&field2=value2",
			expectedResponseHeader: "application/x-www-form-urlencoded; charset=UTF-8",
		},
	}

	// 3. 循环执行测试用例
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 创建一个 handler，用于验证解密后的请求状态
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if string(body) != tc.expectedResponseBody {
					t.Errorf("期望的 body 是 %q, 但实际得到 %q", tc.expectedResponseBody, string(body))
				}
				// 仅在成功场景下验证 header
				if tc.expectedStatusCode == http.StatusOK && tc.expectedResponseHeader != "" {
					if r.Header.Get("Content-Type") != tc.expectedResponseHeader {
						t.Errorf("期望的 Content-Type 是 %q, 但实际得到 %q", tc.expectedResponseHeader, r.Header.Get("Content-Type"))
					}
				}
				w.WriteHeader(http.StatusOK)
			})

			// 用中间件包装 handler
			handler := middleware(nextHandler)
			server := httptest.NewServer(handler)
			defer server.Close()

			// 创建请求
			req, err := http.NewRequest(tc.method, server.URL, tc.requestBody())
			if err != nil {
				t.Fatalf("创建请求失败: %v", err)
			}
			if tc.requestContentType != "" {
				req.Header.Set("Content-Type", tc.requestContentType)
			}

			// 发送请求
			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("发送请求失败: %v", err)
			}
			defer resp.Body.Close()

			// 验证状态码
			if resp.StatusCode != tc.expectedStatusCode {
				t.Errorf("期望的状态码是 %d, 但实际得到 %d", tc.expectedStatusCode, resp.StatusCode)
			}
		})
	}
}
