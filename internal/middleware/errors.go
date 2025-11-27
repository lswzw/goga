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

// LogError 记录一个带有标准请求上下文的错误级别的日志。
func LogError(r *http.Request, msg string, args ...any) {
	logArgs := []any{
		"client_ip", GetClientIP(r),
		"method", r.Method,
		"uri", r.RequestURI,
		"host", r.Host,
		"user_agent", r.UserAgent(),
	}
	logArgs = append(logArgs, args...)
	slog.Error(msg, logArgs...)
}

// LogWarn 记录一个带有标准请求上下文的警告级别的日志。
func LogWarn(r *http.Request, msg string, args ...any) {
	logArgs := []any{
		"client_ip", GetClientIP(r),
		"method", r.Method,
		"uri", r.RequestURI,
		"host", r.Host,
		"user_agent", r.UserAgent(),
	}
	logArgs = append(logArgs, args...)
	slog.Warn(msg, logArgs...)
}

// WriteJSONError 向客户端发送一个标准化的 JSON 错误响应。
// 它记录错误，然后写入一个包含机器可读错误码和人类可读错误信息的 JSON 对象。
func WriteJSONError(w http.ResponseWriter, r *http.Request, statusCode int, errorCode, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := ErrorResponse{}
	response.Error.Code = errorCode
	response.Error.Message = message

	// 使用新的辅助函数记录错误
	LogError(r, "HTTP error response sent",
		"status", statusCode,
		"code", errorCode,
		"message", message,
	)

	// 检查编码错误是一个好习惯，尽管在这里很少发生。
	if err := json.NewEncoder(w).Encode(response); err != nil {
		// 这里的错误发生在响应写入期间，无法使用 LogError 因为可能没有有效的 http.Request
		slog.Error("Failed to encode JSON error response", "error", err)
	}
}