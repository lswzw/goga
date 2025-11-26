// Copyright (c) 2025 wangke <464829928@qq.com>
//
// This software is released under the AGPL-3.0 license.
// For more details, see the LICENSE file in the root directory.

package middleware

import (
	"bytes"
	"io"
	"log/slog"
)

// peekReader 用于预读取请求体的前几个字节，用于快速判断是否为加密载荷
// 它实现了 io.Reader 接口，可以无缝替换原始的 io.Reader
type peekReader struct {
	source    io.Reader // 原始数据源
	peekBuf   []byte    // 预读取缓冲区
	peeked    int       // 已预读取的字节数
	peekPos   int       // 当前预读取位置
	exhausted bool      // 预读取缓冲区是否已耗尽
	bufferPtr *[]byte   // 指向内存池中的原始缓冲区，用于归还
}

// newPeekReader 创建一个新的 peekReader
func newPeekReader(source io.Reader) *peekReader {
	// 从内存池获取缓冲区
	buf := GlobalBufferPool.GetSmallBuffer()

	return &peekReader{
		source:    source,
		peekBuf:   buf[:0], // 重置长度但保留容量
		bufferPtr: &buf,
	}
}

// Peek 读取指定字节数用于检测，但不消费这些数据
// 后续的 Read 调用会重新返回这些数据
func (pr *peekReader) Peek(n int) ([]byte, error) {
	// 如果已经预读取了足够的数据，直接返回
	if pr.peeked >= n {
		return pr.peekBuf[:n], nil
	}

	// 计算还需要读取的字节数
	need := n - pr.peeked
	if need > cap(pr.peekBuf)-pr.peeked {
		// 如果缓冲区容量不足，扩展到所需大小
		newSize := pr.peeked + need
		if newSize > cap(pr.peekBuf) {
			newBuf := make([]byte, newSize)
			copy(newBuf, pr.peekBuf)
			pr.peekBuf = newBuf
		}
	}

	// 从源读取更多数据
	nRead, err := io.ReadAtLeast(pr.source, pr.peekBuf[pr.peeked:cap(pr.peekBuf)], need)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}

	pr.peeked += nRead
	pr.peekBuf = pr.peekBuf[:pr.peeked]

	// 如果读取的数据不足，返回实际读取的数据
	if pr.peeked < n {
		return pr.peekBuf, nil
	}

	return pr.peekBuf[:n], nil
}

// Read 实现 io.Reader 接口
func (pr *peekReader) Read(p []byte) (int, error) {
	// 首先返回预读取缓冲区中的数据
	if pr.peekPos < pr.peeked {
		n := copy(p, pr.peekBuf[pr.peekPos:])
		pr.peekPos += n
		slog.Debug("peekReader: 从预读缓冲区读取", "bytes", n)
		return n, nil
	}

	// 预读取缓冲区已耗尽，直接从源读取
	if !pr.exhausted {
		slog.Debug("peekReader: 预读缓冲区已耗尽，将从原始 source 读取")
		pr.exhausted = true
	}
	n, err := pr.source.Read(p)
	// 在返回错误前记录，以便捕获所有情况
	if err != nil {
		slog.Debug("peekReader: 从原始 source 读取返回", "bytes", n, "error", err)
	}
	return n, err
}

// Close 关闭 reader 并归还缓冲区到内存池
func (pr *peekReader) Close() error {
	slog.Debug("peekReader: Close 被调用")
	if pr.bufferPtr != nil {
		// 归还缓冲区到内存池
		GlobalBufferPool.PutSmallBuffer(pr.bufferPtr)
		pr.bufferPtr = nil
		slog.Debug("peekReader: 缓冲区已归还内存池")
	}

	// 如果源实现了 Close，则关闭它
	if closer, ok := pr.source.(io.Closer); ok {
		slog.Debug("peekReader: 关闭原始 source")
		return closer.Close()
	}
	slog.Debug("peekReader: 原始 source 不是 io.Closer")

	return nil
}

// IsEncryptedRequest 检测请求体是否为加密格式
// 它会读取前几个字节来判断 JSON 格式，而不消费整个请求体
func IsEncryptedRequest(pr *peekReader) bool {
	// 读取前 100 字节用于检测 JSON 格式
	peekData, err := pr.Peek(100)
	if err != nil {
		return false
	}

	// 去除前导空白字符
	peekData = bytes.TrimSpace(peekData)
	if len(peekData) == 0 {
		return false
	}

	// 检查是否以 { 开始（JSON 对象）
	if peekData[0] != '{' {
		return false
	}

	// 检查是否包含 "token" 和 "encrypted" 字段
	hasToken := bytes.Contains(peekData, []byte("\"token\""))
	hasEncrypted := bytes.Contains(peekData, []byte("\"encrypted\""))

	return hasToken && hasEncrypted
}

// DetectEncryptedRequest 检测并返回是否为加密请求。
// 这是一个便利函数，封装了创建 peekReader 和检测的逻辑。
// 无论请求是否加密，它都会返回一个可读的 peekReader，调用者有责任关闭它。
func DetectEncryptedRequest(body io.Reader) (bool, *peekReader, error) {
	pr := newPeekReader(body)
	isEncrypted := IsEncryptedRequest(pr)
	// 始终返回 peekReader，让调用者决定如何处理。
	// 这可以防止原始 body 被过早关闭。
	return isEncrypted, pr, nil
}
