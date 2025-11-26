// Copyright (c) 2025 wangke <464828@qq.com>
//
// This software is released under the AGPL-3.0 license.
// For more details, see the LICENSE file in the root directory.

// decrypt_reader.go 流式解密实现
package middleware

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"goga/internal/crypto"
	"io"
)

// decryptState 解密状态机
type decryptState int

const (
	stateParseJSON decryptState = iota
	stateParseBinaryPayload
	stateDone
	stateError
)

// decryptReader 流式解密器，实现在读取过程中实时解密
type decryptReader struct {
	source io.Reader    // 原始数据源（peekReader）
	key    []byte       // 解密密钥
	state  decryptState // 当前状态

	// JSON 解析相关
	token     string // 从 JSON 中提取的 token
	encrypted string // 从 JSON 中提取的 encrypted 字段

	// 二进制载荷解析相关
	payloadBuf     *bytes.Buffer // 解密后的载荷缓冲区
	contentType    string        // 原始 Content-Type
	contentTypeLen int           // Content-Type 长度

	// 错误状态
	err error // 存储错误信息，避免重复创建错误对象
}

// newDecryptReader 创建一个新的流式解密器
func newDecryptReader(source io.Reader, key []byte) *decryptReader {
	// 创建密钥副本，避免外部修改
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	return &decryptReader{
		source: source,
		key:    keyCopy,
		state:  stateParseJSON,
	}
}

// Read 实现 io.Reader 接口
func (dr *decryptReader) Read(p []byte) (int, error) {
	switch dr.state {
	case stateParseJSON:
		return dr.parseJSON(p)
	case stateParseBinaryPayload:
		return dr.readPayload(p)
	case stateDone:
		return 0, io.EOF
	case stateError:
		return 0, dr.getError()
	default:
		return 0, errors.New("invalid decrypt state")
	}
}

// parseJSON 解析 JSON 格式的加密载荷
func (dr *decryptReader) parseJSON(p []byte) (int, error) {
	// 使用缓冲池获取临时缓冲区
	jsonBuf := GlobalBufferPool.GetMediumBuffer()
	defer func() {
		GlobalBufferPool.PutMediumBuffer(&jsonBuf)
	}()

	// 使用 bufio.Reader 读取 JSON 数据
	reader := bufio.NewReader(dr.source)

	// 读取完整的 JSON 数据到缓冲池
	jsonData := jsonBuf[:0] // 重置长度但保留容量
	for {
		b, err := reader.ReadByte()
		if err != nil {
			dr.setError("读取JSON数据失败: %v", err)
			return 0, dr.err
		}

		jsonData = append(jsonData, b)
		if b == '}' {
			break
		}

		// 防止恶意请求导致内存耗尽
		if len(jsonData) >= cap(jsonBuf) {
			dr.setError("JSON数据过大，超过最大限制 %d", cap(jsonBuf))
			return 0, dr.err
		}
	}

	// 解析 JSON
	var payload struct {
		Token     string `json:"token"`
		Encrypted string `json:"encrypted"`
	}

	if err := json.Unmarshal(jsonData, &payload); err != nil {
		dr.setError("JSON解析失败: %v", err)
		return 0, dr.err
	}

	if payload.Token == "" || payload.Encrypted == "" {
		dr.setError("加密载荷无效: 缺少token或encrypted字段")
		return 0, dr.err
	}

	dr.token = payload.Token
	dr.encrypted = payload.Encrypted

	// 执行 Base64 解码，使用缓冲池
	baseBuf := GlobalBufferPool.GetMediumBuffer()
	defer func() {
		GlobalBufferPool.PutMediumBuffer(&baseBuf)
	}()

	encryptedData, err := base64.StdEncoding.DecodeString(dr.encrypted)
	if err != nil {
		dr.setError("Base64解码失败: %v", err)
		return 0, dr.err
	}

	// 执行 AES 解密
	decryptedData, err := crypto.DecryptAES256GCM(dr.key, encryptedData)
	if err != nil {
		dr.setError("AES解密失败: %v", err)
		return 0, dr.err
	}

	// 解析二进制载荷
	if len(decryptedData) < 1 {
		dr.setError("解密载荷过短: 格式无效")
		return 0, dr.err
	}

	dr.contentTypeLen = int(decryptedData[0])
	bodyOffset := 1 + dr.contentTypeLen

	if len(decryptedData) < bodyOffset {
		dr.setError("解密载荷损坏: Content-Type长度不匹配")
		return 0, dr.err
	}

	dr.contentType = string(decryptedData[1:bodyOffset])
	dr.payloadBuf = bytes.NewBuffer(decryptedData[bodyOffset:])
	dr.state = stateParseBinaryPayload

	// 递归调用 Read 继续处理
	return dr.Read(p)
}

// readPayload 读取解密后的原始载荷数据
func (dr *decryptReader) readPayload(p []byte) (int, error) {
	return dr.payloadBuf.Read(p)
}

// setError 设置错误状态和详细信息
func (dr *decryptReader) setError(format string, args ...any) {
	dr.state = stateError
	dr.err = fmt.Errorf(format, args...)
}

// getError 返回当前错误状态
func (dr *decryptReader) getError() error {
	if dr.err != nil {
		return dr.err
	}
	return errors.New("decrypt reader in error state")
}

// Close 关闭 reader 并释放资源
func (dr *decryptReader) Close() error {
	// 释放缓冲区资源
	if dr.payloadBuf != nil {
		dr.payloadBuf = nil
	}

	// 清零敏感数据
	if len(dr.key) > 0 {
		for i := range dr.key {
			dr.key[i] = 0
		}
	}
	dr.key = nil

	// 如果源实现了 Close，则关闭它
	if closer, ok := dr.source.(io.Closer); ok {
		return closer.Close()
	}

	return nil
}

// GetContentType 返回解密后的原始 Content-Type
func (dr *decryptReader) GetContentType() string {
	return dr.contentType
}

// GetToken 返回加密载荷中的 token
func (dr *decryptReader) GetToken() string {
	return dr.token
}

// Reset 重置解密器状态，使其可以复用
func (dr *decryptReader) Reset(source io.Reader, key []byte) {
	// 清理现有资源
	if dr.payloadBuf != nil {
		dr.payloadBuf.Reset()
	}

	// 清零旧密钥
	if len(dr.key) > 0 {
		for i := range dr.key {
			dr.key[i] = 0
		}
	}

	// 设置新状态
	dr.source = source
	dr.key = make([]byte, len(key))
	copy(dr.key, key)
	dr.state = stateParseJSON
	dr.token = ""
	dr.encrypted = ""
	dr.contentType = ""
	dr.contentTypeLen = 0
	dr.err = nil
}
