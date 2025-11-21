// Copyright (c) 2025 wangke <464829928@qq.com>
//
// This software is released under the AGPL-3.0 license.
// For more details, see the LICENSE file in the root directory.

package gateway

import (
	"time"
)

// KeyCacher 定义了密钥缓存的通用接口。
// 任何密钥缓存实现（如内存缓存或 Redis 缓存）都必须实现此接口。
type KeyCacher interface {
	// Set 向缓存中添加一个带特定 TTL 的密钥。
	Set(token string, key []byte, ttl time.Duration)

	// Get 从缓存中检索一个密钥。如果找到且未过期，则返回密钥和 true。
	// 如果密钥未找到或已过期，则返回 nil 和 false。
	Get(token string) ([]byte, bool)

	// Stop 用于停止缓存的后台清理或释放资源，以实现优雅关闭。
	// 对于内存缓存，这可能用于停止清理 goroutine；对于 Redis 缓存，这可能用于关闭连接池。
	Stop()
}
