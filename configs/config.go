// Copyright (c) 2025 wangke <464829928@qq.com>
//
// This software is released under the AGPL-3.0 license.
// For more details, see the LICENSE file in the root directory.

package configs

import (
	"log"
	"strings"

	"github.com/spf13/viper"
)

// Config 存储所有应用程序的配置

type Config struct {
	Server ServerConfig `mapstructure:"server"`

	BackendURL string `mapstructure:"backend_url"`

	Encryption EncryptionConfig `mapstructure:"encryption"`

	KeyCache KeyCacheConfig `mapstructure:"key_cache"`

	ScriptInjection ScriptInjectionConfig `mapstructure:"script_injection"`

	Log LogConfig `mapstructure:"log"`
}

// LogConfig 存储日志相关的配置

type LogConfig struct {
	LogLevel string `mapstructure:"level"`

	OutputPaths []string `mapstructure:"output_paths"`
}

// ServerConfig 存储服务器相关的配置

type ServerConfig struct {
	Port string `mapstructure:"port"`

	TLSCertPath string `mapstructure:"tls_cert_path"`

	TLSKeyPath string `mapstructure:"tls_key_path"`
}

// EncryptionConfig 存储加密相关的配置

type EncryptionConfig struct {
	Enabled           bool     `mapstructure:"enabled"`
	MustEncryptRoutes []string `mapstructure:"must_encrypt_routes"`
}

// RedisConfig 存储 Redis 连接相关的配置

type RedisConfig struct {
	Addr string `mapstructure:"addr"`

	Password string `mapstructure:"password"`

	DB int `mapstructure:"db"`
}

// KeyCacheConfig 存储密钥缓存相关的配置

type KeyCacheConfig struct {
	Type string `mapstructure:"type"` // "in-memory" or "redis"

	TTLSeconds int `mapstructure:"ttl_seconds"`

	Redis RedisConfig `mapstructure:"redis"`
}

// ScriptInjectionConfig 存储脚本注入相关的配置

type ScriptInjectionConfig struct {
	ScriptContent string `mapstructure:"script_content"`
}

// LoadConfig 从文件和环境变量中读取配置

func LoadConfig() (config Config, err error) {

	// 设置默认值

	viper.SetDefault("server.port", "8080")

	viper.SetDefault("backend_url", "http://localhost:3000")

	viper.SetDefault("log.level", "info")

	viper.SetDefault("log.output_paths", []string{"stdout"}) // 默认输出到标准输出

	viper.SetDefault("encryption.enabled", true)

	viper.SetDefault("script_injection.script_content", `<script src="/goga-crypto.min.js" defer></script>`)

	// KeyCache 默认配置

	viper.SetDefault("key_cache.type", "in-memory")

	viper.SetDefault("key_cache.ttl_seconds", 300) // 5 minutes

	viper.SetDefault("key_cache.redis.addr", "localhost:6379")

	viper.SetDefault("key_cache.redis.password", "")

	viper.SetDefault("key_cache.redis.db", 0)

	// 从配置文件加载

	viper.SetConfigName("config") // 配置文件名 (不带扩展名)

	viper.SetConfigType("yaml") // 配置文件类型

	viper.AddConfigPath("./configs") // 配置文件路径

	viper.AddConfigPath(".") // 可选的当前目录路径

	// 读取配置文件

	err = viper.ReadInConfig()

	if err != nil {

		if _, ok := err.(viper.ConfigFileNotFoundError); ok {

			// 配置文件未找到是可接受的，因为可以使用环境变量

			log.Printf("DEBUG: 配置文件未找到，将使用默认值和环境变量：%v", err)

		} else {

			// 配置文件被找到但解析错误

			log.Printf("ERROR: 读取配置文件失败，文件存在但解析错误：%v", err)

			return config, err

		}

	} else {

		log.Printf("DEBUG: 成功加载配置文件：%s", viper.ConfigFileUsed())

	}

	// 启用环境变量绑定

	viper.SetEnvPrefix("GOGA")

	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	viper.AutomaticEnv()

	// 将配置解组到结构体

	err = viper.Unmarshal(&config)

	return

}
