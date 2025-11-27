package middleware

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

// contextKey is a custom type to avoid key collisions in context.
type contextKey string

const (
	// RequestIDKey is the key for storing the request ID in the context.
	RequestIDKey contextKey = "requestID"
)

// RequestID is a middleware that injects a request ID into the context of each request.
// If the "X-Request-ID" header is present, it will be used. Otherwise, a new UUID will be generated.
// The request ID is also added to the response headers.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get request ID from header
		requestID := r.Header.Get("X-Request-ID")

		// If the header is empty, generate a new request ID
		if requestID == "" {
			requestID = uuid.New().String()
		}

		// Set the request ID in the response header
		w.Header().Set("X-Request-ID", requestID)

		// Create a new context with the request ID and pass it to the next handler
		ctx := context.WithValue(r.Context(), RequestIDKey, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
