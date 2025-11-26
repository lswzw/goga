package middleware

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// ErrorResponse 定义了标准 JSON 错误响应格式。
type ErrorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// WriteJSONError 向客户端发送一个标准化的 JSON 错误响应。
// 它记录错误，然后写入一个包含机器可读错误码和人类可读错误信息的 JSON 对象。
func WriteJSONError(w http.ResponseWriter, r *http.Request, statusCode int, errorCode, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := ErrorResponse{}
	response.Error.Code = errorCode
	response.Error.Message = message

	// 记录带有更多上下文的错误
	slog.Error("HTTP error response sent",
		"method", r.Method,
		"path", r.URL.Path,
		"status", statusCode,
		"code", errorCode,
		"message", message,
	)

	// 检查编码错误是一个好习惯，尽管在这里很少发生。
	if err := json.NewEncoder(w).Encode(response); err != nil {
		// 如果编码失败，我们无法发送 JSON 错误，因此记录日志。
		slog.Error("Failed to encode JSON error response", "error", err)
	}
}
