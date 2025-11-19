package gateway

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// NewProxy 创建并返回一个配置好的反向代理处理器
func NewProxy(targetURL string) (http.Handler, error) {
	// 解析后端目标 URL
	target, err := url.Parse(targetURL)
	if err != nil {
		log.Fatalf("无法解析目标 URL: %v", err)
		return nil, err
	}

	// 创建一个反向代理
	proxy := httputil.NewSingleHostReverseProxy(target)

	// 修改 Director 来自定义请求如何被转发
	// NewSingleHostReverseProxy 已经为我们设置了大部分
	// 我们需要确保 Host 头部被正确设置
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = target.Host
	}

	return proxy, nil
}
