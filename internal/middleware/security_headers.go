package middleware

import (
	"net/http"
)

// SecurityHeadersMiddleware 为所有响应添加推荐的安全头部。
// 这些头部有助于抵御 XSS、点击劫持等常见的 Web 攻击。
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 添加安全头部
		headers := w.Header()

		// X-Content-Type-Options: nosniff
		// 防止浏览器对响应内容进行 MIME 类型嗅探，避免将非脚本类型的内容（如纯文本）误判为脚本并执行。
		headers.Set("X-Content-Type-Options", "nosniff")

		// X-Frame-Options: SAMEORIGIN
		// 防止页面被嵌入到其他网站的 frame/iframe 中，有效抵御点击劫持攻击。
		// "SAMEORIGIN" 表示只允许同源域名嵌入。
		headers.Set("X-Frame-Options", "SAMEORIGIN")

		// X-XSS-Protection: 0
		// 这个头部用于控制旧版浏览器内置的 XSS 过滤器。现代浏览器已废弃此头部，并推荐使用 Content-Security-Policy。
		// 设置为 "0" 可以显式禁用这个可能存在漏洞的旧功能。
		headers.Set("X-XSS-Protection", "0")

		// Content-Security-Policy (CSP)
		// 这是一个强大的 XSS 防护机制，但策略与具体应用强相关。
		// 一个过于严格的通用策略可能会破坏后端应用的正常功能（如加载外部 CDN 脚本、字体、图片等）。
		// 因此，这里只作为占位符，生产环境中应通过配置下发一个为具体应用量身定制的策略。
		// headers.Set("Content-Security-Policy", "default-src 'self';")

		// Strict-Transport-Security (HSTS)
		// 强制客户端（如浏览器）使用 HTTPS 与服务器创建连接。
		// 只有在确定整个站点都支持并使用 TLS/SSL 时才应启用此头部。
		if r.TLS != nil {
			headers.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		next.ServeHTTP(w, r)
	})
}
