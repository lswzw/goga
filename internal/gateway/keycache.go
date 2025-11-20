package gateway

import (
	"log/slog"
	"sync"
	"time"
)

// cacheEntry 是缓存中的条目定义
type cacheEntry struct {
	key       []byte
	expiresAt time.Time
}

// KeyCache 是一个支持 TTL 的线程安全内存密钥缓存
type KeyCache struct {
	mu      sync.RWMutex
	items   map[string]cacheEntry
	stop    chan struct{} // 用于停止后台清理 goroutine
}

// NewKeyCache 创建一个新的密钥缓存，并启动一个后台清理 goroutine
func NewKeyCache(cleanupInterval time.Duration) *KeyCache {
	kc := &KeyCache{
		items: make(map[string]cacheEntry),
		stop:  make(chan struct{}),
	}

	// 只有在 cleanupInterval 大于 0 时才启动清理 goroutine
	if cleanupInterval > 0 {
		go kc.cleanupLoop(cleanupInterval)
	}

	return kc
}

// Set 向缓存中添加一个带特定 TTL 的密钥
func (kc *KeyCache) Set(token string, key []byte, ttl time.Duration) {
	kc.mu.Lock()
	defer kc.mu.Unlock()

	expiresAt := time.Now().Add(ttl)
	kc.items[token] = cacheEntry{
		key:       key,
		expiresAt: expiresAt,
	}
	slog.Debug("密钥已缓存", "token", token, "ttl", ttl.String())
}

// Get 从缓存中检索一个密钥。如果找到且未过期，则返回密钥和 true。
// 如果密钥未找到或已过期，则返回 nil 和 false。
// 过期的密钥在被访问时会被删除。
func (kc *KeyCache) Get(token string) ([]byte, bool) {
	kc.mu.RLock()
	entry, found := kc.items[token]
	kc.mu.RUnlock()

	if !found {
		slog.Debug("缓存未命中", "token", token)
		return nil, false
	}

	if time.Now().After(entry.expiresAt) {
		// 如果条目已过期，我们获取写锁并再次检查，然后删除它
		kc.mu.Lock()
		// 再次检查，因为在获取写锁的过程中，条目可能已被更新或已被其他 goroutine 删除
		entry, found = kc.items[token]
		if found && time.Now().After(entry.expiresAt) {
			delete(kc.items, token)
			slog.Debug("访问到过期密钥并已删除", "token", token)
			found = false // 标记为未找到
		}
		kc.mu.Unlock()
		if !found {
			return nil, false
		}
	}
	slog.Debug("缓存命中", "token", token)
	return entry.key, true
}

// Stop 停止后台清理 goroutine，用于优雅关闭
func (kc *KeyCache) Stop() {
	// 检查 stop channel 是否已关闭或为 nil，避免重复关闭导致 panic
	select {
	case <-kc.stop:
		// 已经关闭或从未启动
		return
	default:
		slog.Debug("正在停止密钥缓存的后台清理任务...")
		close(kc.stop)
	}
}


// cleanupLoop 定期从缓存中删除过期的条目
func (kc *KeyCache) cleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			kc.deleteExpired()
		case <-kc.stop:
			slog.Debug("已停止密钥缓存的后台清理任务。")
			return
		}
	}
}

// deleteExpired 遍历所有条目并删除任何已过期的条目
func (kc *KeyCache) deleteExpired() {
	kc.mu.Lock()
	defer kc.mu.Unlock()

	now := time.Now()
	deletedCount := 0
	for token, entry := range kc.items {
		if now.After(entry.expiresAt) {
			delete(kc.items, token)
			deletedCount++
		}
	}
	if deletedCount > 0 {
		slog.Debug("密钥缓存后台清理完成", "删除数量", deletedCount)
	}
}
