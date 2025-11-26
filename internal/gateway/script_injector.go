// Copyright (c) 2025 wangke <464829928@qq.com>
//
// This software is released under the AGPL-3.0 license.
// For more details, see the LICENSE file in the root directory.

package gateway

import (
	"bytes"
	"io"
	"sync"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
)

// injectorState 定义了 scriptInjector 的内部状态
type injectorState int

const (
	stateSearching       injectorState = iota // 正在搜索目标标签
	stateInjectingScript                      // 正在注入脚本
	stateInjectingTag                         // 正在注入目标标签本身
	statePassthrough                          // 注入完成或未找到标签，直接透传剩余数据
)

// scriptInjector 是一个 io.ReadCloser，它以流式方式在目标标签前注入脚本，且内存占用低。
type scriptInjector struct {
	upstreamReader io.Reader
	script         []byte
	searchTag      []byte
	state          injectorState
	buffer         []byte     // 用于缓存上游数据的内部缓冲区
	bufferPtr      *[]byte    // 指向池中缓冲区的指针，用于归还
	searchPos      int        // 缓冲区中已处理（已发送）数据的结束位置
	bufferEnd      int        // 缓冲区中有效数据的结束位置
	scriptReadPos  int        // 已读取脚本的长度
	tagReadPos     int        // 已读取标签的长度
	pool           *sync.Pool // 用于获取/归还缓冲区的池
	upstreamEOF    bool       // 标记上游是否已达 EOF
}

var bufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 8192)
		return &b
	},
}

// NewScriptInjector 创建一个新的 scriptInjector 实例。
func NewScriptInjector(upstream io.Reader, script []byte) *scriptInjector {
	bufferPtr := bufferPool.Get().(*[]byte)
	return &scriptInjector{
		upstreamReader: upstream,
		script:         script,
		searchTag:      []byte("</body>"),
		state:          stateSearching,
		buffer:         *bufferPtr,
		bufferPtr:      bufferPtr,
		pool:           &bufferPool,
	}
}

// Read 实现 io.Reader 接口。
func (si *scriptInjector) Read(p []byte) (n int, err error) {
	// 循环以处理状态转换，确保在单次Read调用中尽可能取得进展
	for {
		switch si.state {
		case stateInjectingScript:
			if si.scriptReadPos >= len(si.script) {
				si.state = stateInjectingTag
				continue // 转换状态并立即处理
			}
			n = copy(p, si.script[si.scriptReadPos:])
			si.scriptReadPos += n
			return n, nil

		case stateInjectingTag:
			if si.tagReadPos >= len(si.searchTag) {
				si.state = statePassthrough
				continue
			}
			n = copy(p, si.searchTag[si.tagReadPos:])
			si.tagReadPos += n
			return n, nil

		case statePassthrough:
			if si.searchPos < si.bufferEnd {
				n = copy(p, si.buffer[si.searchPos:si.bufferEnd])
				si.searchPos += n
				return n, nil
			}
			if si.upstreamEOF {
				return 0, io.EOF
			}
			return si.upstreamReader.Read(p)

		case stateSearching:
			// 1. 整理缓冲区
			if si.searchPos > 0 {
				copy(si.buffer, si.buffer[si.searchPos:si.bufferEnd])
				si.bufferEnd -= si.searchPos
				si.searchPos = 0
			}

			// 2. 填充缓冲区
			if !si.upstreamEOF && si.bufferEnd < len(si.buffer) {
				readN, readErr := si.upstreamReader.Read(si.buffer[si.bufferEnd:])
				if readN > 0 {
					si.bufferEnd += readN
				}
				if readErr != nil {
					if readErr == io.EOF {
						si.upstreamEOF = true
						// 如果缓冲区仍为空，直接切换到透传
						if si.bufferEnd == 0 {
							si.state = statePassthrough
							continue
						}
					} else {
						return 0, readErr
					}
				}
				// 修复：如果 readN == 0 且 readErr == nil，说明上游已无数据可读，视为 EOF
				if readN == 0 && readErr == nil {
					si.upstreamEOF = true
					// 如果缓冲区为空，直接切换到透传模式；否则继续处理剩余数据
					if si.bufferEnd == 0 {
						si.state = statePassthrough
						continue
					}
				}
			}

			// 3. 搜索标签
			if idx := bytes.Index(si.buffer[si.searchPos:si.bufferEnd], si.searchTag); idx != -1 {
				absoluteIdx := si.searchPos + idx
				dataBeforeTag := si.buffer[si.searchPos:absoluteIdx]
				if len(dataBeforeTag) > 0 {
					n = copy(p, dataBeforeTag)
					si.searchPos += n
					return n, nil
				}
				si.searchPos += len(si.searchTag)
				si.state = stateInjectingScript
				continue // 找到标签，立即进入注入状态
			}

			// 4. 未找到标签
			if si.upstreamEOF {
				// EOF时，无论缓冲区长度如何，直接切换到透传并写出所有剩余数据
				if si.searchPos < si.bufferEnd {
					n = copy(p, si.buffer[si.searchPos:si.bufferEnd])
					si.searchPos += n
					if si.searchPos >= si.bufferEnd {
						si.state = statePassthrough
					}
					return n, nil
				}
				si.state = statePassthrough
				continue
			}

			// 5. 写出安全数据
			safeWriteEnd := si.bufferEnd
			if safeWriteEnd > len(si.searchTag) {
				safeWriteEnd -= (len(si.searchTag) - 1)
			} else {
				// 缓冲区中的数据不足以做出安全判断，并且上游还未结束
				// 如果上游已经EOF但缓冲区数据不足，直接切换到透传模式
				if si.upstreamEOF {
					si.state = statePassthrough
					continue
				}
				// 返回 (0, nil) 等待更多数据，这依赖于调用者（如 io.Copy）的重试
				return 0, nil
			}

			if dataToWrite := si.buffer[si.searchPos:safeWriteEnd]; len(dataToWrite) > 0 {
				n = copy(p, dataToWrite)
				si.searchPos += n
				return n, nil
			}

			// 没有可写的安全数据，可能因为searchPos已经赶上了safeWriteEnd
			// 如果上游已经EOF，直接切换到透传模式
			if si.upstreamEOF {
				si.state = statePassthrough
				continue
			}
			// 返回 (0, nil) 等待更多数据
			return 0, nil
		}
	}
}

// Close 实现 io.Closer 接口。
func (si *scriptInjector) Close() error {
	if si.bufferPtr != nil {
		si.searchPos, si.bufferEnd = 0, 0
		si.pool.Put(si.bufferPtr)
		si.buffer = nil
		si.bufferPtr = nil
	}
	if closer, ok := si.upstreamReader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// getDecompressionReader and other helpers...
func getDecompressionReader(encoding string, upstream io.Reader) (io.ReadCloser, error) {
	switch encoding {
	case "gzip":
		return gzip.NewReader(upstream)
	case "br":
		return io.NopCloser(brotli.NewReader(upstream)), nil
	case "zstd":
		r, err := zstd.NewReader(upstream)
		if err != nil {
			return nil, err
		}
		return r.IOReadCloser(), nil
	case "lz4":
		return io.NopCloser(lz4.NewReader(upstream)), nil
	default:
		return nil, nil
	}
}

type nopWriteCloser struct{ io.Writer }

func (nwc *nopWriteCloser) Close() error           { return nil }
func newNopWriteCloser(w io.Writer) io.WriteCloser { return &nopWriteCloser{w} }
func getCompressionWriter(encoding string, downstream io.Writer) (io.WriteCloser, error) {
	switch encoding {
	case "gzip":
		return gzip.NewWriter(downstream), nil
	case "br":
		return brotli.NewWriter(downstream), nil
	case "zstd":
		return zstd.NewWriter(downstream)
	case "lz4":
		return lz4.NewWriter(downstream), nil
	default:
		return newNopWriteCloser(downstream), nil
	}
}
