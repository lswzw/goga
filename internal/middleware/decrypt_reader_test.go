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
	"strings"
	"testing"
)

func TestPeekReader(t *testing.T) {
	// 测试数据
	testData := `{"token":"test123","encrypted":"abc123"}`
	source := strings.NewReader(testData)

	pr := newPeekReader(source)
	defer pr.Close()

	// 测试 Peek
	peeked, err := pr.Peek(10)
	if err != nil {
		t.Fatalf("Peek failed: %v", err)
	}

	if string(peeked) != `{"token":"` {
		t.Errorf("Peek data mismatch: got %s", string(peeked))
	}

	// 测试 Read 仍然能读取完整数据
	result := make([]byte, len(testData))
	n, err := pr.Read(result)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if n != len(testData) {
		t.Errorf("Read length mismatch: got %d, want %d", n, len(testData))
	}

	if string(result) != testData {
		t.Errorf("Read data mismatch: got %s, want %s", string(result), testData)
	}
}

func TestIsEncryptedRequest(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		expected bool
	}{
		{
			name:     "Valid encrypted request",
			data:     `{"token":"abc","encrypted":"def"}`,
			expected: true,
		},
		{
			name:     "Missing token",
			data:     `{"encrypted":"def"}`,
			expected: false,
		},
		{
			name:     "Missing encrypted",
			data:     `{"token":"abc"}`,
			expected: false,
		},
		{
			name:     "Not JSON",
			data:     `plain text`,
			expected: false,
		},
		{
			name:     "Empty",
			data:     "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := strings.NewReader(tt.data)
			pr := newPeekReader(source)
			defer pr.Close()

			result := IsEncryptedRequest(pr)
			if result != tt.expected {
				t.Errorf("IsEncryptedRequest() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDetectEncryptedRequest(t *testing.T) {
	// 测试加密请求
	encryptedData := `{"token":"abc123","encrypted":"def456"}`
	source := strings.NewReader(encryptedData)

	isEncrypted, pr, err := DetectEncryptedRequest(source)
	if err != nil {
		t.Fatalf("DetectEncryptedRequest failed: %v", err)
	}

	if !isEncrypted {
		t.Error("Expected encrypted request, got false")
	}

	if pr == nil {
		t.Error("Expected peekReader, got nil")
	}
	defer pr.Close()

	// 测试普通请求
	plainData := `{"name":"test","value":"data"}`
	source2 := strings.NewReader(plainData)

	isEncrypted2, pr2, err := DetectEncryptedRequest(source2)
	if err != nil {
		t.Fatalf("DetectEncryptedRequest failed: %v", err)
	}

	if isEncrypted2 {
		t.Error("Expected plain request, got true")
	}

	if pr2 == nil {
		t.Error("Expected non-nil peekReader for plain request")
	} else {
		pr2.Close()
	}
}

func TestFindJSONEnd(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		expected int
	}{
		{
			name:     "Simple JSON",
			data:     `{"key":"value"}`,
			expected: 14,
		},
		{
			name:     "JSON with spaces",
			data:     `  {"key":"value"}  `,
			expected: 16,
		},
		{
			name:     "JSON with nested object",
			data:     `{"outer":{"inner":"value"}}`,
			expected: 26,
		},
		{
			name:     "JSON with escaped quotes",
			data:     `{"key":"value\"with\"quotes"}`,
			expected: 28,
		},
		{
			name:     "Invalid JSON - no opening brace",
			data:     `plain text`,
			expected: -1,
		},
		{
			name:     "Incomplete JSON",
			data:     `{"key":"value"`,
			expected: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := findJSONEnd([]byte(tt.data))
			if result != tt.expected {
				t.Errorf("findJSONEnd() = %d, want %d", result, tt.expected)
			}
		})
	}
}

func TestDecryptReader(t *testing.T) {
	// 生成测试密钥
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	// 构造测试数据
	originalContentType := "application/json"
	originalBody := `{"test":"data"}`

	// 构造二进制载荷
	contentTypeBytes := []byte(originalContentType)
	bodyBytes := []byte(originalBody)

	payload := make([]byte, 1+len(contentTypeBytes)+len(bodyBytes))
	payload[0] = byte(len(contentTypeBytes))
	copy(payload[1:], contentTypeBytes)
	copy(payload[1+len(contentTypeBytes):], bodyBytes)

	// 加密数据
	encryptedData, err := crypto.EncryptAES256GCM(key, payload)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Base64 编码
	encryptedBase64 := base64.StdEncoding.EncodeToString(encryptedData)

	// 构造 JSON 载荷
	jsonPayload := map[string]string{
		"token":     "test123",
		"encrypted": encryptedBase64,
	}

	jsonData, err := json.Marshal(jsonPayload)
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}

	// 创建解密器
	source := bytes.NewReader(jsonData)
	dr := newDecryptReader(source, key)
	defer dr.Close()

	// 读取解密后的数据
	result := make([]byte, 1024)
	n, err := dr.Read(result)
	if err != nil && err != bytes.ErrTooLarge {
		t.Fatalf("DecryptReader Read failed: %v", err)
	}

	// 验证结果
	expectedBody := originalBody
	if string(result[:n]) != expectedBody {
		t.Errorf("Decrypted data mismatch: got %s, want %s", string(result[:n]), expectedBody)
	}

	// 验证 Content-Type
	if dr.GetContentType() != originalContentType {
		t.Errorf("Content-Type mismatch: got %s, want %s", dr.GetContentType(), originalContentType)
	}

	// 验证 Token
	if dr.GetToken() != "test123" {
		t.Errorf("Token mismatch: got %s, want test123", dr.GetToken())
	}
}

func TestBufferPool(t *testing.T) {
	// 测试小缓冲区
	buf1 := GlobalBufferPool.GetSmallBuffer()
	if cap(buf1) != SmallBufferSize {
		t.Errorf("Small buffer size mismatch: got %d, want %d", cap(buf1), SmallBufferSize)
	}

	GlobalBufferPool.PutSmallBuffer(&buf1)

	// 测试中等缓冲区
	buf2 := GlobalBufferPool.GetMediumBuffer()
	if cap(buf2) != MediumBufferSize {
		t.Errorf("Medium buffer size mismatch: got %d, want %d", cap(buf2), MediumBufferSize)
	}

	GlobalBufferPool.PutMediumBuffer(&buf2)

	// 测试大缓冲区
	buf3 := GlobalBufferPool.GetLargeBuffer()
	if cap(buf3) != LargeBufferSize {
		t.Errorf("Large buffer size mismatch: got %d, want %d", cap(buf3), LargeBufferSize)
	}

	GlobalBufferPool.PutLargeBuffer(&buf3)
}

func TestBufferManager(t *testing.T) {
	bm := NewBufferManager(nil)

	// 获取一些缓冲区
	_ = bm.GetSmall()
	_ = bm.GetMedium()
	_ = bm.GetLarge()

	// 验证数量
	if bm.Count() != 3 {
		t.Errorf("Buffer manager count mismatch: got %d, want 3", bm.Count())
	}

	// 释放所有缓冲区
	bm.ReleaseAll()

	// 验证清空
	if bm.Count() != 0 {
		t.Errorf("Buffer manager count after release: got %d, want 0", bm.Count())
	}
}
