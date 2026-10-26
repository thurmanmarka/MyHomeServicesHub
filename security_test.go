package main

import (
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestSameOrigin(t *testing.T) {
	tests := []struct {
		method, host, origin string
		want                 bool
	}{
		{"GET", "hub.example.com", "https://evil.example", true},
		{"POST", "hub.example.com", "", true},
		{"POST", "hub.example.com", "https://hub.example.com", true},
		{"POST", "hub.example.com", "https://hub.example.com:8443", true},
		{"POST", "192.168.86.13", "https://192.168.86.13", true},
		{"POST", "[::1]:8080", "http://[::1]:8080", true},
		{"POST", "hub.example.com", "https://evil.example", false},
		{"POST", "hub.example.com", "https://hub.example.com.evil.example", false},
		{"POST", "hub.example.com", "null", false},
		{"DELETE", "hub.example.com", "https://evil.example", false},
	}
	for _, tt := range tests {
		r := httptest.NewRequest(tt.method, "/admin/users/add", nil)
		r.Host = tt.host
		if tt.origin != "" {
			r.Header.Set("Origin", tt.origin)
		}
		if got := sameOrigin(r); got != tt.want {
			t.Errorf("%s Host=%s Origin=%q: got %v, want %v", tt.method, tt.host, tt.origin, got, tt.want)
		}
	}
}

func TestDummyPasswordHashIsValid(t *testing.T) {
	cost, err := bcrypt.Cost([]byte(dummyPasswordHash))
	if err != nil {
		t.Fatalf("dummy hash is not a bcrypt hash: %v", err)
	}
	if cost != bcrypt.DefaultCost {
		t.Errorf("dummy hash cost %d, want %d so it takes as long as a real check", cost, bcrypt.DefaultCost)
	}
}

func TestIsHTTPSTrustsOnlyLocalProxy(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")

	r.RemoteAddr = "127.0.0.1:50000"
	if !isHTTPS(r) {
		t.Error("header from nginx on this machine should be trusted")
	}
	r.RemoteAddr = "203.0.113.9:50000"
	if isHTTPS(r) {
		t.Error("header from a remote client should not be trusted")
	}
}
