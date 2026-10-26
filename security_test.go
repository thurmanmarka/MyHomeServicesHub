package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func TestIsLocalIP(t *testing.T) {
	defer func() { localNets = nil }()
	for ip, want := range map[string]bool{
		"192.168.86.50": true,
		"10.0.0.5":      true,
		"127.0.0.1":     true,
		"::1":           true,
		"203.0.113.9":   false,
		"8.8.8.8":       false,
		"not-an-ip":     false,
	} {
		if got := isLocalIP(ip); got != want {
			t.Errorf("default networks: isLocalIP(%s) = %v, want %v", ip, got, want)
		}
	}

	_, n, _ := net.ParseCIDR("192.168.86.0/24")
	localNets = []*net.IPNet{n}
	if isLocalIP("10.0.0.5") {
		t.Error("10.0.0.5 is outside the configured network")
	}
	if !isLocalIP("192.168.86.50") || !isLocalIP("127.0.0.1") {
		t.Error("the configured network and this machine should be local")
	}
}

func TestLocalOnlySessionEndsOffNetwork(t *testing.T) {
	saved := config
	defer func() { config = saved }()
	config.Auth.LocalOnlyUsers = []string{"admin"}
	config.Auth.IdleMinutes = 60
	config.Auth.Users = []ConfigUser{{Username: "admin", Role: "admin"}, {Username: "mark", Role: "admin"}}
	auth = newConfigStore("unused.yaml")

	for _, name := range []string{"admin", "mark"} {
		auth.CreateSession(name+"-token", Session{Username: name, ExpiresAt: time.Now().Add(time.Hour)}, "", "")
	}
	request := func(token, ip string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "127.0.0.1:50000" // via nginx
		r.Header.Set("X-Real-IP", ip)
		r.AddCookie(&http.Cookie{Name: "session_token", Value: token})
		return r
	}

	if currentSession(request("admin-token", "192.168.86.50")) == nil {
		t.Error("admin should be signed in at home")
	}
	if currentSession(request("admin-token", "203.0.113.9")) != nil {
		t.Error("admin's session should not work from outside")
	}
	if currentSession(request("mark-token", "203.0.113.9")) == nil {
		t.Error("other admins should work from outside")
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
