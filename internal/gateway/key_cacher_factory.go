// Copyright (c) 2025 wangke <464829928@qq.com>
//
// This software is released under the AGPL-3.0 license.
// For more details, see the LICENSE file in the root directory.

package gateway

import (
	"fmt"
	"goga/internal/security"
	"log/slog"
	"time"

	"goga/configs"
)

// NewKeyCacherFactory 根据配置创建并返回一个 KeyCacher 实例。
func NewKeyCacherFactory(cfg configs.KeyCacheConfig) (security.KeyCacher, error) {
	switch cfg.Type {
	case "in-memory":
		slog.Info("正在初始化 In-Memory KeyCache")
		// 将 Encryption.KeyCacheTTLSeconds 传递给内存缓存
		return NewInMemoryKeyCache(time.Duration(cfg.TTLSeconds) * time.Second), nil
	case "redis":
		slog.Info("正在初始化 Redis KeyCache")
		redisCfg := RedisKeyCacheConfig{
			Addr:       cfg.Redis.Addr,
			Password:   cfg.Redis.Password,
			DB:         cfg.Redis.DB,
			TTLSeconds: cfg.TTLSeconds,
		}
		return NewRedisKeyCache(redisCfg)
	default:
		return nil, fmt.Errorf("不支持的 key_cache 类型: %s", cfg.Type)
	}
}
