package configs

import (
	"strings"

	"github.com/spf13/viper"
)

// Config 存储所有应用程序的配置
type Config struct {
	Server          ServerConfig
	BackendURL      string `mapstructure:"backend_url"`
	Encryption      EncryptionConfig
	ScriptInjection ScriptInjectionConfig `mapstructure:"script_injection"`
	LogLevel        string `mapstructure:"log_level"`
}

// ServerConfig 存储服务器相关的配置
type ServerConfig struct {
	Port        string `mapstructure:"port"`
	TLSCertPath string `mapstructure:"tls_cert_path"`
	TLSKeyPath  string `mapstructure:"tls_key_path"`
}

// EncryptionConfig 存储加密相关的配置
type EncryptionConfig struct {
	Enabled             bool   `mapstructure:"enabled"`
	MasterKey           string `mapstructure:"master_key"`
	KeyCacheTTLSeconds int    `mapstructure:"key_cache_ttl_seconds"`
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
	viper.SetDefault("log_level", "info")
	viper.SetDefault("encryption.enabled", true)
	viper.SetDefault("encryption.key_cache_ttl_seconds", 60)
	viper.SetDefault("script_injection.script_content", `<script src="/goga-crypto.js" defer></script>`)

	// 从配置文件加载
	viper.SetConfigName("config")    // 配置文件名 (不带扩展名)
	viper.SetConfigType("yaml")      // 配置文件类型
	viper.AddConfigPath("./configs") // 配置文件路径
	viper.AddConfigPath(".")         // 可选的当前目录路径

	// 读取配置文件
	err = viper.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// 配置文件被找到但解析错误
			return
		}
		// 配置文件未找到是可接受的，因为可以使用环境变量
	}

	// 启用环境变量绑定
	viper.SetEnvPrefix("GOGA")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// 将配置解组到结构体
	err = viper.Unmarshal(&config)
	return
}