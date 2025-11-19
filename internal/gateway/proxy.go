package gateway

import (
	"bytes"
	"io/ioutil"
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
		// 检查响应类型是否为 HTML
		if strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
			// 读取响应体
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			resp.Body.Close() // 及时关闭原始响应体

			// 注入脚本
			script := config.ScriptInjection.ScriptContent
			body = bytes.Replace(body, []byte("</body>"), []byte(script+"</body>"), -1)

			// 创建一个新的响应体
			newBody := ioutil.NopCloser(bytes.NewReader(body))
			resp.Body = newBody
			resp.ContentLength = int64(len(body))
			// 因为我们修改了响应体，所以移除 Content-Encoding 头部
			// 防止浏览器尝试解压一个未压缩的响应
			resp.Header.Del("Content-Encoding")
		}
		return nil
	}

	return proxy, nil
}
