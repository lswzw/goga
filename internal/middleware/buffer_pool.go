// Copyright (c) 2025 wangke <464829928@qq.com>
//
// This software is released under the AGPL-3.0 license.
// For more details, see the LICENSE file in the root directory.

package middleware

import (
	"sync"
)

// BufferPool 统一的缓冲区内存池管理器
// 为解密过程中的各种缓冲区提供高效的内存复用
type BufferPool struct {
	// 小缓冲区池，用于 JSON 解析、头部检测等
	smallBuffers sync.Pool

	// 中等缓冲区池，用于 Base64 解码、AES 解密等
	mediumBuffers sync.Pool

	// 大缓冲区池，用于大型请求体处理
	largeBuffers sync.Pool
}

const (
	// SmallBufferSize 小缓冲区大小，用于 JSON 解析、格式检测等
	SmallBufferSize = 512

	// MediumBufferSize 中等缓冲区大小，用于 Base64 解码、AES 解密等
	MediumBufferSize = 8192

	// LargeBufferSize 大缓冲区大小，用于处理大型请求体
	LargeBufferSize = 65536 // 64KB
)

var (
	// 全局缓冲区池实例
	GlobalBufferPool = NewBufferPool()
)

// NewBufferPool 创建一个新的缓冲区池
func NewBufferPool() *BufferPool {
	return &BufferPool{
		smallBuffers: sync.Pool{
			New: func() any {
				b := make([]byte, 0, SmallBufferSize)
				return &b
			},
		},
		mediumBuffers: sync.Pool{
			New: func() any {
				b := make([]byte, 0, MediumBufferSize)
				return &b
			},
		},
		largeBuffers: sync.Pool{
			New: func() any {
				b := make([]byte, 0, LargeBufferSize)
				return &b
			},
		},
	}
}

// GetSmallBuffer 获取小缓冲区
func (bp *BufferPool) GetSmallBuffer() []byte {
	return *(bp.smallBuffers.Get().(*[]byte))
}

// GetMediumBuffer 获取中等缓冲区
func (bp *BufferPool) GetMediumBuffer() []byte {
	return *(bp.mediumBuffers.Get().(*[]byte))
}

// GetLargeBuffer 获取大缓冲区
func (bp *BufferPool) GetLargeBuffer() []byte {
	return *(bp.largeBuffers.Get().(*[]byte))
}

// PutSmallBuffer 归还小缓冲区
func (bp *BufferPool) PutSmallBuffer(buf *[]byte) {
	// 重置长度但保留容量
	*buf = (*buf)[:0]
	bp.smallBuffers.Put(buf)
}

// PutMediumBuffer 归还中等缓冲区
func (bp *BufferPool) PutMediumBuffer(buf *[]byte) {
	// 重置长度但保留容量
	*buf = (*buf)[:0]
	bp.mediumBuffers.Put(buf)
}

// PutLargeBuffer 归还大缓冲区
func (bp *BufferPool) PutLargeBuffer(buf *[]byte) {
	// 重置长度但保留容量
	*buf = (*buf)[:0]
	bp.largeBuffers.Put(buf)
}

// PutBuffer 根据缓冲区大小自动归还到合适的池
func (bp *BufferPool) PutBuffer(buf []byte) {
	switch cap(buf) {
	case SmallBufferSize:
		bp.PutSmallBuffer(&buf)
	case MediumBufferSize:
		bp.PutMediumBuffer(&buf)
	case LargeBufferSize:
		bp.PutLargeBuffer(&buf)
		// 对于其他大小的缓冲区，不进行池化，让 GC 处理
	}
}

// BufferManager 缓冲区管理器，用于跟踪和批量归还缓冲区
type BufferManager struct {
	pool    *BufferPool
	buffers [][]byte
}

// NewBufferManager 创建一个新的缓冲区管理器
func NewBufferManager(pool *BufferPool) *BufferManager {
	if pool == nil {
		pool = GlobalBufferPool
	}
	return &BufferManager{
		pool:    pool,
		buffers: make([][]byte, 0, 8), // 预分配容量
	}
}

// GetSmall 获取小缓冲区并跟踪
func (bm *BufferManager) GetSmall() []byte {
	buf := bm.pool.GetSmallBuffer()
	bm.buffers = append(bm.buffers, buf)
	return buf
}

// GetMedium 获取中等缓冲区并跟踪
func (bm *BufferManager) GetMedium() []byte {
	buf := bm.pool.GetMediumBuffer()
	bm.buffers = append(bm.buffers, buf)
	return buf
}

// GetLarge 获取大缓冲区并跟踪
func (bm *BufferManager) GetLarge() []byte {
	buf := bm.pool.GetLargeBuffer()
	bm.buffers = append(bm.buffers, buf)
	return buf
}

// ReleaseAll 释放所有跟踪的缓冲区
func (bm *BufferManager) ReleaseAll() {
	for _, buf := range bm.buffers {
		bm.pool.PutBuffer(buf)
	}
	bm.buffers = bm.buffers[:0] // 清空切片但保留容量
}

// Count 返回当前管理的缓冲区数量
func (bm *BufferManager) Count() int {
	return len(bm.buffers)
}
