package test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"goga/configs"
	"goga/internal/crypto"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"crypto/rand"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFullEncryptionFlow(t *testing.T) {
	// 1. 准备工作: 启动模拟后端和 goga 服务器
	backend := StartMockBackendServer()
	defer backend.StopFunc()

	cfg := &configs.Config{
		Server: configs.ServerConfig{
			Port: "0", // 使用随机端口
		},
		BackendURL: backend.URL,
		Log: configs.LogConfig{
			LogLevel:    "error",
			OutputPaths: []string{"stdout"},
		},
		Encryption: configs.EncryptionConfig{
			Enabled: true,
		},
		KeyCache: configs.KeyCacheConfig{
			Type:       "in-memory",
			TTLSeconds: 300, // 5 minutes
		},
		ScriptInjection: configs.ScriptInjectionConfig{
			ScriptContent: `<script src="/goga-crypto.min.js" defer></script>`, // 模拟默认注入内容
		},
	}

	goga, err := StartGoGaServer(cfg)
	require.NoError(t, err, "启动 goga 服务器失败")
	defer goga.StopFunc()

	// --- 测试步骤 ---

	// 2. 验证 GET 请求 HTML 页面时脚本是否被注入
	t.Run("应该向 html 响应中注入脚本", func(t *testing.T) {
		resp, err := http.Get(goga.URL + "/some-html")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "text/html", resp.Header.Get("Content-Type"))

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), `<script src="/goga-crypto.min.js" defer></script></body>`)
	})

	// 3. 从 API 获取加密密钥和令牌
	var key string
	var token string
	t.Run("应该能够获取密钥和令牌", func(t *testing.T) {
		resp, err := http.Get(goga.URL + "/goga/api/v1/key")
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		var keyResp struct {
			Key   string `json:"key"`
			Token string `json:"token"`
			TTL   int    `json:"ttl"`
		}
		err = json.NewDecoder(resp.Body).Decode(&keyResp)
		require.NoError(t, err)

		assert.NotEmpty(t, keyResp.Key, "密钥不应为空")
		assert.NotEmpty(t, keyResp.Token, "令牌不应为空")
		assert.True(t, keyResp.TTL > 0, "TTL 应该大于 0")

		key = keyResp.Key
		token = keyResp.Token
	})

	// 4. 模拟客户端加密并 POST 加密数据
	t.Run("后端应该能收到解密后的数据", func(t *testing.T) {
		// 明文载荷和内容类型
		formData := url.Values{}
		formData.Set("username", "admin")
		formData.Set("password", "password")
		originalBody := formData.Encode()
		originalContentType := "application/x-www-form-urlencoded"

		// 构建用于加密的二进制载荷
		contentTypeBytes := []byte(originalContentType)
		contentTypeLen := byte(len(contentTypeBytes))

		var payloadToEncrypt []byte
		payloadToEncrypt = append(payloadToEncrypt, contentTypeLen)
		payloadToEncrypt = append(payloadToEncrypt, contentTypeBytes...)
		payloadToEncrypt = append(payloadToEncrypt, []byte(originalBody)...)

		// 解码 base64 格式的密钥
		aesKey, err := base64.StdEncoding.DecodeString(key)
		require.NoError(t, err)

		// 加密数据
		encryptedData, err := crypto.EncryptAES256GCM(aesKey, payloadToEncrypt)
		require.NoError(t, err)

		// 创建最终的 JSON 载荷
		finalPayload := struct {
			Token     string `json:"token"`
			Encrypted string `json:"encrypted"`
		}{
			Token:     token,
			Encrypted: base64.StdEncoding.EncodeToString(encryptedData),
		}
		payloadBytes, err := json.Marshal(finalPayload)
		require.NoError(t, err)

		// 将加密后的请求发送到 goga
		req, err := http.NewRequest("POST", goga.URL+"/api/login", bytes.NewReader(payloadBytes))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// 断言请求成功
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// 5. 验证后端收到了正确的、解密后的数据
		backend.LastRequest.RLock()
		defer backend.LastRequest.RUnlock()

		// Content-Type 应该被解密中间件还原
		assert.Equal(t, "application/x-www-form-urlencoded", backend.LastRequest.Header.Get("Content-Type"))

		// 解析实际收到的表单数据
		actualForm, err := url.ParseQuery(string(backend.LastRequest.Body))
		require.NoError(t, err)
		// 解析预期的表单数据
		expectedForm, err := url.ParseQuery(originalBody)
		require.NoError(t, err)

		// 比较解析后的表单数据，忽略顺序
		assert.Equal(t, expectedForm, actualForm)
	})

	t.Run("不应该向非 html 响应中注入脚本", func(t *testing.T) {
		resp, err := http.Get(goga.URL + "/other-content")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		assert.False(t, strings.Contains(string(body), "goga-crypto.min.js"))
	})
}

func TestInvalidToken(t *testing.T) {
	// 1. 准备工作: 启动模拟后端和 goga 服务器
	backend := StartMockBackendServer()
	defer backend.StopFunc()

	cfg := &configs.Config{
		Server: configs.ServerConfig{
			Port: "0", // 使用随机端口
		},
		BackendURL: backend.URL,
		Log: configs.LogConfig{
			LogLevel:    "error",
			OutputPaths: []string{"stdout"},
		},
		Encryption: configs.EncryptionConfig{
			Enabled: true, // 加密启用
		},
		KeyCache: configs.KeyCacheConfig{
			Type:       "in-memory",
			TTLSeconds: 300, // 5 分钟
		},
		ScriptInjection: configs.ScriptInjectionConfig{
			ScriptContent: `<script src="/goga-crypto.min.js" defer></script>`, // 模拟默认注入内容
		},
	}

	goga, err := StartGoGaServer(cfg)
	require.NoError(t, err, "启动 goga 服务器失败")
	defer goga.StopFunc()

	t.Run("应该为无效或过期的令牌返回 401 Unauthorized", func(t *testing.T) {
		// 1. 生成一个合法的加密载荷，但使用一个无效的令牌
		formData := url.Values{}
		formData.Set("username", "admin")
		formData.Set("password", "password")
		originalBody := formData.Encode()
		originalContentType := "application/x-www-form-urlencoded"

		contentTypeBytes := []byte(originalContentType)
		contentTypeLen := byte(len(contentTypeBytes))

		var payloadToEncrypt []byte
		payloadToEncrypt = append(payloadToEncrypt, contentTypeLen)
		payloadToEncrypt = append(payloadToEncrypt, contentTypeBytes...)
		payloadToEncrypt = append(payloadToEncrypt, []byte(originalBody)...)

		// 生成一个随机密钥用于加密 (实际测试中 goga 不会用它解密)
		randomKey := make([]byte, crypto.AES256KeySize)
		_, err = rand.Read(randomKey) // 使用 crypto/rand 生成随机密钥
		require.NoError(t, err)

		encryptedData, err := crypto.EncryptAES256GCM(randomKey, payloadToEncrypt)
		require.NoError(t, err)

		// 创建最终的 JSON 载荷，但使用一个不存在的令牌
		finalPayload := struct {
			Token     string `json:"token"`
			Encrypted string `json:"encrypted"`
		}{
			Token:     "invalid-or-expired-token", // 无效令牌
			Encrypted: base64.StdEncoding.EncodeToString(encryptedData),
		}
		payloadBytes, err := json.Marshal(finalPayload)
		require.NoError(t, err)

		// 将请求发送到 goga
		req, err := http.NewRequest("POST", goga.URL+"/api/login", bytes.NewReader(payloadBytes))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// 断言 goga 返回 401 Unauthorized
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		// 验证后端没有收到任何请求 (因为 goga 应该在解密中间件中拦截了)
		backend.LastRequest.RLock()
		defer backend.LastRequest.RUnlock()
		assert.Nil(t, backend.LastRequest.Body)     // 检查是否为空或上一个请求的残留
		assert.Empty(t, backend.LastRequest.Header) // 检查是否为空
	})
}

func TestEncryptionDisabledFlow(t *testing.T) {
	// 1. 准备工作: 启动模拟后端和 goga 服务器 (加密禁用)
	backend := StartMockBackendServer()
	defer backend.StopFunc()

	cfg := &configs.Config{
		Server: configs.ServerConfig{
			Port: "0", // 使用随机端口
		},
		BackendURL: backend.URL,
		Log: configs.LogConfig{
			LogLevel:    "error",
			OutputPaths: []string{"stdout"},
		},
		Encryption: configs.EncryptionConfig{
			Enabled: false, // 加密禁用
		},
		KeyCache: configs.KeyCacheConfig{
			Type:       "in-memory",
			TTLSeconds: 300, // 5 分钟
		},
		ScriptInjection: configs.ScriptInjectionConfig{
			ScriptContent: `<script src="/goga-crypto.min.js" defer></script>`, // 模拟默认注入内容
		},
	}

	goga, err := StartGoGaServer(cfg)
	require.NoError(t, err, "启动 goga 服务器失败")
	defer goga.StopFunc()

	// --- 测试步骤 ---

	// 2. 验证 GET 请求 HTML 页面时脚本是否未被注入
	t.Run("在加密禁用时，不应该向 html 响应中注入脚本", func(t *testing.T) {
		resp, err := http.Get(goga.URL + "/some-html")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "text/html", resp.Header.Get("Content-Type"))

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.NotContains(t, string(body), `<script src="/goga-crypto.min.js" defer></script></body>`)
	})

	// 3. 验证标准 POST 请求是否未经修改地成功代理
	t.Run("在加密禁用时，标准 POST 请求应该未经修改地成功代理", func(t *testing.T) {
		// 原始 JSON 载荷
		originalPayload := map[string]string{
			"username": "admin", // 使用正确的凭据
			"password": "password",
		}
		payloadBytes, err := json.Marshal(originalPayload)
		require.NoError(t, err)

		// 发送标准 POST 请求到 goga
		req, err := http.NewRequest("POST", goga.URL+"/api/login", bytes.NewReader(payloadBytes))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// 断言请求成功
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// 验证后端收到了原始的、未经修改的 JSON 数据
		backend.LastRequest.RLock()
		defer backend.LastRequest.RUnlock()

		assert.Equal(t, "application/json", backend.LastRequest.Header.Get("Content-Type"))
		assert.JSONEq(t, string(payloadBytes), string(backend.LastRequest.Body))
	})
}

func TestStaticAssetDelivery(t *testing.T) {
	// 1. 准备工作: 启动 goga 服务器
	backend := StartMockBackendServer()
	defer backend.StopFunc()

	cfg := &configs.Config{
		Server: configs.ServerConfig{
			Port: "0", // 使用随机端口
		},
		BackendURL: backend.URL,
		Log: configs.LogConfig{
			LogLevel:    "error",
			OutputPaths: []string{"stdout"},
		},
		Encryption: configs.EncryptionConfig{
			Enabled: true,
		},
		KeyCache: configs.KeyCacheConfig{
			Type:       "in-memory",
			TTLSeconds: 300, // 5 分钟
		},
		ScriptInjection: configs.ScriptInjectionConfig{
			ScriptContent: `<script src="/goga-crypto.min.js" defer></script>`, // 模拟默认注入内容
		},
	}

	goga, err := StartGoGaServer(cfg)
	require.NoError(t, err, "启动 goga 服务器失败")
	defer goga.StopFunc()

	t.Run("应该正确提供 goga-crypto.min.js 静态文件", func(t *testing.T) {
		resp, err := http.Get(goga.URL + "/goga-crypto.min.js")
		require.NoError(t, err)
		defer resp.Body.Close()

		// 断言状态码为 200 OK
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		// 断言 Content-Type 是 JavaScript
		assert.Contains(t, resp.Header.Get("Content-Type"), "text/javascript")

		// 断言响应体不为空
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.NotEmpty(t, body, "goga-crypto.min.js 响应体不应为空")
	})
}

func TestHealthCheck(t *testing.T) {
	// 1. 准备工作: 启动 goga 服务器
	// 健康检查不依赖于后端，因此不需要启动模拟后端
	cfg := &configs.Config{
		Server: configs.ServerConfig{
			Port: "0", // 使用随机端口
		},
		BackendURL: "", // 无需后端
		Log: configs.LogConfig{
			LogLevel:    "error",
			OutputPaths: []string{"stdout"},
		},
		Encryption: configs.EncryptionConfig{
			Enabled: false, // 加密可以禁用
		},
		KeyCache: configs.KeyCacheConfig{
			Type: "in-memory",
		},
	}

	goga, err := StartGoGaServer(cfg)
	require.NoError(t, err, "启动 goga 服务器失败")
	defer goga.StopFunc()

	t.Run("应该为 /healthz 端点返回 200 OK", func(t *testing.T) {
		// 2. 向 /healthz 端点发送 GET 请求
		resp, err := http.Get(goga.URL + "/healthz")
		require.NoError(t, err)
		defer resp.Body.Close()

		// 3. 断言状态码为 200 OK
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// 4. 断言响应体为 "OK"
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "OK", string(body))
	})
}
