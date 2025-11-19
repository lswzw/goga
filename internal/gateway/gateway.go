package gateway

import (
	"fmt"
	"net/http"
)

// Gateway represents the web form encryption gateway.
type Gateway struct {
	// TODO: Add fields for encryption keys, backend URL, etc.
}

// NewGateway creates a new Gateway instance.
func NewGateway() (*Gateway, error) {
	// TODO: Initialize encryption, load configuration
	return &Gateway{}, nil
}

// ServeHTTP implements the http.Handler interface for the gateway.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Request received: %s %s\n", r.Method, r.URL.Path)

	// TODO: Implement form data interception and encryption
	// TODO: Forward encrypted data to the backend
	// TODO: Handle response from backend

	fmt.Fprintf(w, "Request processed by GoGa Gateway (not yet encrypted/proxied)!")
}
