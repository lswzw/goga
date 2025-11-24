package gateway

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestKeyCache_SetAndGet 测试基本的设置和获取功能
func TestInMemoryKeyCache_SetAndGet(t *testing.T) {
	cache := NewInMemoryKeyCache(1 * time.Minute)
	defer cache.Stop()

	token := "test_token_1"
	key := []byte("secret_key_1")
	ttl := 5 * time.Minute

	cache.Set(token, key, ttl)

	retrievedKey, found := cache.Get(token)
	if !found {
		t.Fatal("未能找到刚刚设置的密钥")
	}

	if !bytes.Equal(key, retrievedKey) {
		t.Errorf("获取到的密钥与原始密钥不匹配。 got %v, want %v", retrievedKey, key)
	}
}

// TestKeyCache_GetExpired 测试在访问时获取已过期的密钥
func TestInMemoryKeyCache_GetExpired(t *testing.T) {
	cache := NewInMemoryKeyCache(1 * time.Minute)
	defer cache.Stop()

	token := "test_token_expired"
	key := []byte("secret_key_expired")
	ttl := 1 * time.Millisecond

	cache.Set(token, key, ttl)

	// 等待足够长的时间以确保密钥已过期
	time.Sleep(5 * time.Millisecond)

	_, found := cache.Get(token)
	if found {
		t.Fatal("不应找到已过期的密钥")
	}
}

// TestKeyCache_GetNonExistent 测试获取一个不存在的密钥
func TestInMemoryKeyCache_GetNonExistent(t *testing.T) {
	cache := NewInMemoryKeyCache(1 * time.Minute)
	defer cache.Stop()

	_, found := cache.Get("non_existent_token")
	if found {
		t.Fatal("不应找到不存在的密钥")
	}
}

// TestKeyCache_Cleanup 测试后台清理 goroutine 是否正常工作
func TestInMemoryKeyCache_Cleanup(t *testing.T) {
	cleanupInterval := 10 * time.Millisecond
	cache := NewInMemoryKeyCache(cleanupInterval)
	defer cache.Stop()

	// 设置一个比清理间隔短的 TTL
	token := "test_token_cleanup"
	key := []byte("secret_key_cleanup")
	ttl := 1 * time.Millisecond
	cache.Set(token, key, ttl)

	// 设置一个不会过期的
	cache.Set("non_expiring_token", []byte("key"), 1*time.Minute)

	// 等待足够长的时间以确保清理 goroutine 已运行
	time.Sleep(cleanupInterval * 3)

	cache.mu.RLock()
	_, found := cache.items[token]
	cache.mu.RUnlock()

	if found {
		t.Errorf("后台清理后，过期的密钥仍然存在")
	}

	_, found = cache.Get("non_expiring_token")
	if !found {
		t.Errorf("未过期的密钥不应该被清理")
	}
}

// TestKeyCache_Concurrency 测试并发读写
func TestInMemoryKeyCache_Concurrency(t *testing.T) {
	cache := NewInMemoryKeyCache(5 * time.Millisecond)
	defer cache.Stop()

	var wg sync.WaitGroup
	numGoroutines := 100

	// 并发写入
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			token := fmt.Sprintf("token_%d", i)
			key := []byte(fmt.Sprintf("key_%d", i))
			cache.Set(token, key, 100*time.Millisecond)
		}(i)
	}

	// 并发读取
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			token := fmt.Sprintf("token_%d", i)
			key := []byte(fmt.Sprintf("key_%d", i))

			// 可能会读到，也可能由于过期或还未写入而读不到，这里主要测试会不会 panic
			retrievedKey, found := cache.Get(token)
			if found && !bytes.Equal(key, retrievedKey) {
				t.Errorf("并发读取时数据不一致 for token %s", token)
			}
		}(i)
	}

	wg.Wait()
}
