package gateway

import (
	"bytes"
	"compress/gzip"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"goga/configs"
)

// NewProxy 创建并返回一个配置好的反向代理处理器
func NewProxy(config *configs.Config) (http.Handler, error) {
	// 解析后端目标 URL
	target, err := url.Parse(config.BackendURL)
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

	// 添加 ModifyResponse 函数来注入脚本
	proxy.ModifyResponse = func(resp *http.Response) error {
		// 仅在响应成功且类型为 HTML 时才注入脚本
		if resp.StatusCode == http.StatusOK && strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			if err := resp.Body.Close(); err != nil {
				return err
			}

			// 如果响应被压缩了，需要先解压
			if resp.Header.Get("Content-Encoding") == "gzip" {
				gz, err := gzip.NewReader(bytes.NewReader(body))
				if err != nil {
					return err
				}
				body, err = io.ReadAll(gz)
				if err != nil {
					// 确保在出错时也关闭gz
					gz.Close()
					return err
				}
				gz.Close()
			}

			// 注入脚本
			script := config.ScriptInjection.ScriptContent
			body = bytes.Replace(body, []byte("</body>"), []byte(script+"</body>"), -1)

			// 创建一个新的响应体
			newBody := io.NopCloser(bytes.NewReader(body))
			resp.Body = newBody

			// 为确保干净的状态，删除所有可能冲突的头部
			resp.Header.Del("Content-Encoding")
			resp.Header.Del("Transfer-Encoding")
			resp.Header.Del("Content-Length")

			// 设置新的、正确的 Content-Length
			resp.ContentLength = int64(len(body))
		}
		return nil
	}

	return proxy, nil
}
