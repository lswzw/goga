// Copyright (c) 2025 wangke <464829928@qq.com>
//
// This software is released under the AGPL-3.0 license.
// For more details, see the LICENSE file in the root directory.

package middleware

import (
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// DecryptMetrics 解密性能指标
type DecryptMetrics struct {
	// 请求计数
	TotalRequests     int64 // 总请求数
	EncryptedRequests int64 // 加密请求数
	DecryptedRequests int64 // 成功解密请求数
	FailedRequests    int64 // 解密失败请求数

	// 性能指标
	TotalDecryptTime int64 // 总解密时间（纳秒）
	MinDecryptTime   int64 // 最小解密时间（纳秒）
	MaxDecryptTime   int64 // 最大解密时间（纳秒）

	// 内存指标
	TotalMemoryUsed  int64 // 总内存使用量（字节）
	BufferPoolHits   int64 // 缓冲区池命中次数
	BufferPoolMisses int64 // 缓冲区池未命中次数

	// 错误统计
	TokenErrors   int64 // Token 相关错误
	DecryptErrors int64 // 解密错误
	FormatErrors  int64 // 格式错误

	// 时间戳
	StartTime      time.Time
	LastUpdateTime time.Time

	mutex sync.RWMutex
}

var (
	// 全局指标实例
	GlobalDecryptMetrics = NewDecryptMetrics()
)

// NewDecryptMetrics 创建新的解密指标实例
func NewDecryptMetrics() *DecryptMetrics {
	now := time.Now()
	return &DecryptMetrics{
		StartTime:      now,
		LastUpdateTime: now,
		MinDecryptTime: int64(^uint64(0) >> 1), // 最大 int64 值
	}
}

// RecordRequest 记录请求
func (dm *DecryptMetrics) RecordRequest(isEncrypted bool) {
	atomic.AddInt64(&dm.TotalRequests, 1)
	if isEncrypted {
		atomic.AddInt64(&dm.EncryptedRequests, 1)
	}
	dm.updateLastTime()
}

// RecordDecryptSuccess 记录成功解密
func (dm *DecryptMetrics) RecordDecryptSuccess(duration time.Duration, memoryUsed int64) {
	atomic.AddInt64(&dm.DecryptedRequests, 1)

	// 记录解密时间
	durationNanos := duration.Nanoseconds()
	atomic.AddInt64(&dm.TotalDecryptTime, durationNanos)

	// 更新最小和最大时间
	dm.updateMinMaxTime(durationNanos)

	// 记录内存使用
	atomic.AddInt64(&dm.TotalMemoryUsed, memoryUsed)

	dm.updateLastTime()
}

// RecordDecryptFailure 记录解密失败
func (dm *DecryptMetrics) RecordDecryptFailure(errorType string) {
	atomic.AddInt64(&dm.FailedRequests, 1)

	switch errorType {
	case "token":
		atomic.AddInt64(&dm.TokenErrors, 1)
	case "decrypt":
		atomic.AddInt64(&dm.DecryptErrors, 1)
	case "format":
		atomic.AddInt64(&dm.FormatErrors, 1)
	}

	dm.updateLastTime()
}

// RecordBufferPoolHit 记录缓冲区池命中
func (dm *DecryptMetrics) RecordBufferPoolHit() {
	atomic.AddInt64(&dm.BufferPoolHits, 1)
}

// RecordBufferPoolMiss 记录缓冲区池未命中
func (dm *DecryptMetrics) RecordBufferPoolMiss() {
	atomic.AddInt64(&dm.BufferPoolMisses, 1)
}

// updateMinMaxTime 更新最小和最大解密时间
func (dm *DecryptMetrics) updateMinMaxTime(duration int64) {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	if duration < dm.MinDecryptTime {
		dm.MinDecryptTime = duration
	}
	if duration > dm.MaxDecryptTime {
		dm.MaxDecryptTime = duration
	}
}

// updateLastTime 更新最后更新时间
func (dm *DecryptMetrics) updateLastTime() {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()
	dm.LastUpdateTime = time.Now()
}

// GetSnapshot 获取指标快照
func (dm *DecryptMetrics) GetSnapshot() DecryptMetricsSnapshot {
	dm.mutex.RLock()
	defer dm.mutex.RUnlock()

	totalRequests := atomic.LoadInt64(&dm.TotalRequests)
	encryptedRequests := atomic.LoadInt64(&dm.EncryptedRequests)
	decryptedRequests := atomic.LoadInt64(&dm.DecryptedRequests)
	failedRequests := atomic.LoadInt64(&dm.FailedRequests)
	totalDecryptTime := atomic.LoadInt64(&dm.TotalDecryptTime)
	totalMemoryUsed := atomic.LoadInt64(&dm.TotalMemoryUsed)
	bufferPoolHits := atomic.LoadInt64(&dm.BufferPoolHits)
	bufferPoolMisses := atomic.LoadInt64(&dm.BufferPoolMisses)
	tokenErrors := atomic.LoadInt64(&dm.TokenErrors)
	decryptErrors := atomic.LoadInt64(&dm.DecryptErrors)
	formatErrors := atomic.LoadInt64(&dm.FormatErrors)

	return DecryptMetricsSnapshot{
		TotalRequests:     totalRequests,
		EncryptedRequests: encryptedRequests,
		DecryptedRequests: decryptedRequests,
		FailedRequests:    failedRequests,
		TotalDecryptTime:  totalDecryptTime,
		MinDecryptTime:    dm.MinDecryptTime,
		MaxDecryptTime:    dm.MaxDecryptTime,
		TotalMemoryUsed:   totalMemoryUsed,
		BufferPoolHits:    bufferPoolHits,
		BufferPoolMisses:  bufferPoolMisses,
		TokenErrors:       tokenErrors,
		DecryptErrors:     decryptErrors,
		FormatErrors:      formatErrors,
		StartTime:         dm.StartTime,
		LastUpdateTime:    dm.LastUpdateTime,
	}
}

// DecryptMetricsSnapshot 指标快照
type DecryptMetricsSnapshot struct {
	TotalRequests     int64
	EncryptedRequests int64
	DecryptedRequests int64
	FailedRequests    int64
	TotalDecryptTime  int64
	MinDecryptTime    int64
	MaxDecryptTime    int64
	TotalMemoryUsed   int64
	BufferPoolHits    int64
	BufferPoolMisses  int64
	TokenErrors       int64
	DecryptErrors     int64
	FormatErrors      int64
	StartTime         time.Time
	LastUpdateTime    time.Time
}

// GetAverageDecryptTime 获取平均解密时间
func (s DecryptMetricsSnapshot) GetAverageDecryptTime() time.Duration {
	if s.DecryptedRequests == 0 {
		return 0
	}
	return time.Duration(s.TotalDecryptTime / s.DecryptedRequests)
}

// GetEncryptedRequestRate 获取加密请求比例
func (s DecryptMetricsSnapshot) GetEncryptedRequestRate() float64 {
	if s.TotalRequests == 0 {
		return 0
	}
	return float64(s.EncryptedRequests) / float64(s.TotalRequests) * 100
}

// GetSuccessRate 获取解密成功率
func (s DecryptMetricsSnapshot) GetSuccessRate() float64 {
	if s.EncryptedRequests == 0 {
		return 0
	}
	return float64(s.DecryptedRequests) / float64(s.EncryptedRequests) * 100
}

// GetBufferPoolHitRate 获取缓冲区池命中率
func (s DecryptMetricsSnapshot) GetBufferPoolHitRate() float64 {
	total := s.BufferPoolHits + s.BufferPoolMisses
	if total == 0 {
		return 0
	}
	return float64(s.BufferPoolHits) / float64(total) * 100
}

// LogMetrics 记录指标到日志
func (s DecryptMetricsSnapshot) LogMetrics() {
	slog.Info("解密性能指标",
		"总请求数", s.TotalRequests,
		"加密请求数", s.EncryptedRequests,
		"成功解密数", s.DecryptedRequests,
		"失败请求数", s.FailedRequests,
		"加密请求比例", s.GetEncryptedRequestRate(),
		"解密成功率", s.GetSuccessRate(),
		"平均解密时间", s.GetAverageDecryptTime(),
		"最小解密时间", time.Duration(s.MinDecryptTime),
		"最大解密时间", time.Duration(s.MaxDecryptTime),
		"总内存使用", s.TotalMemoryUsed,
		"缓冲区池命中率", s.GetBufferPoolHitRate(),
		"Token错误", s.TokenErrors,
		"解密错误", s.DecryptErrors,
		"格式错误", s.FormatErrors,
		"运行时长", time.Since(s.StartTime),
	)
}

// MetricsTimer 性能计时器
type MetricsTimer struct {
	startTime time.Time
	metrics   *DecryptMetrics
}

// NewMetricsTimer 创建新的计时器
func NewMetricsTimer(metrics *DecryptMetrics) *MetricsTimer {
	return &MetricsTimer{
		startTime: time.Now(),
		metrics:   metrics,
	}
}

// Stop 停止计时并记录结果
func (mt *MetricsTimer) Stop(memoryUsed int64) {
	duration := time.Since(mt.startTime)
	mt.metrics.RecordDecryptSuccess(duration, memoryUsed)
}

// GetMemoryUsage 获取当前内存使用情况
func GetMemoryUsage() (uint64, uint64) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.Alloc, m.TotalAlloc
}

// LogSystemMetrics 记录系统内存指标
func LogSystemMetrics() {
	alloc, totalAlloc := GetMemoryUsage()
	slog.Debug("系统内存指标",
		"当前内存使用", alloc,
		"累计内存分配", totalAlloc,
		"协程数", runtime.NumGoroutine(),
	)
}
