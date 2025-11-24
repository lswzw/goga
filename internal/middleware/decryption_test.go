package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type mockKeyCacher struct{}

func (m *mockKeyCacher) Set(token string, key []byte, ttl time.Duration) {}
func (m *mockKeyCacher) Get(token string) ([]byte, bool) {
	if token == "test_token" {
		return []byte("test_key"), true
	}
	return nil, false
}
func (m *mockKeyCacher) Stop() {}

func TestDecryptionMiddleware(t *testing.T) {
	// Create a mock KeyCacher
	mockCache := &mockKeyCacher{}

	// Create a handler to be wrapped by the middleware
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Create the middleware
	middleware := DecryptionMiddleware(mockCache)

	// Create a test server
	handler := middleware(nextHandler)
	server := httptest.NewServer(handler)
	defer server.Close()

	// Create a request
	req, err := http.NewRequest("POST", server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create a client and send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Check the status code
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}
}
