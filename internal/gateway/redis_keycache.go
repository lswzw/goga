package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisKeyCacheConfig 定义了 RedisKeyCache 的配置。
type RedisKeyCacheConfig struct {
	Addr     string
	Password string
	DB       int // 数据库索引
	TTLSeconds int // 密钥的 TTL (秒)
}

// RedisKeyCache 是一个基于 Redis 的 KeyCacher 实现。
type RedisKeyCache struct {
	client *redis.Client
	ctx    context.Context // 用于 Redis 操作的上下文
}

// NewRedisKeyCache 创建并返回一个新的 RedisKeyCache 实例。
func NewRedisKeyCache(cfg RedisKeyCacheConfig) (KeyCacher, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	// 尝试 Ping Redis 服务器以验证连接。
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := client.Ping(ctx).Result()
	if err != nil {
		return nil, fmt.Errorf("无法连接到 Redis: %w", err)
	}

	slog.Info("RedisKeyCache 初始化成功", "addr", cfg.Addr, "db", cfg.DB)

	return &RedisKeyCache{
		client: client,
		ctx:    context.Background(), // 使用一个长期上下文
	}, nil
}

// Set 向 Redis 缓存中添加一个带特定 TTL 的密钥。
func (rc *RedisKeyCache) Set(token string, key []byte, ttl time.Duration) {
	err := rc.client.Set(rc.ctx, token, key, ttl).Err()
	if err != nil {
		slog.Error("RedisKeyCache: 设置密钥失败", "token", token, "error", err)
	} else {
		slog.Debug("RedisKeyCache: 密钥已设置", "token", token, "ttl", ttl.String())
	}
}

// Get 从 Redis 缓存中检索一个密钥。
// 如果找到且未过期，则返回密钥和 true。
// 如果密钥未找到或已过期，则返回 nil 和 false。
func (rc *RedisKeyCache) Get(token string) ([]byte, bool) {
	val, err := rc.client.Get(rc.ctx, token).Bytes()
	if err == redis.Nil {
		slog.Debug("RedisKeyCache: 缓存未命中或已过期", "token", token)
		return nil, false
	}
	if err != nil {
		slog.Error("RedisKeyCache: 获取密钥失败", "token", token, "error", err)
		return nil, false
	}
	slog.Debug("RedisKeyCache: 缓存命中", "token", token)
	return val, true
}

// Stop 关闭 Redis 客户端连接。
func (rc *RedisKeyCache) Stop() {
	err := rc.client.Close()
	if err != nil {
		slog.Error("RedisKeyCache: 关闭 Redis 连接失败", "error", err)
	} else {
		slog.Info("RedisKeyCache: Redis 连接已关闭")
	}
}
