package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Server struct {
		Port int `yaml:"port"`
	} `yaml:"server"`
	Auth struct {
		Enabled       bool   `yaml:"enabled"`
		SessionSecret string `yaml:"session_secret"`
		Users         []struct {
			Username string `yaml:"username"`
			Password string `yaml:"password"` // bcrypt hash
			Role     string `yaml:"role"`
		} `yaml:"users"`
	} `yaml:"auth"`
	Services []struct {
		Name         string   `yaml:"name"`
		Description  string   `yaml:"description"`
		Icon         string   `yaml:"icon"`
		Path         string   `yaml:"path"`
		Enabled      bool     `yaml:"enabled"`
		AllowedRoles []string `yaml:"allowed_roles"`
	} `yaml:"services"`
}

type Session struct {
	Username  string
	Role      string
	ExpiresAt time.Time
}

var config Config
var templates *template.Template
var sessions = make(map[string]*Session)
var sessionsMux sync.RWMutex

func main() {
	// Load configuration
	if err := loadConfig("config.yaml"); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Load templates
	var err error
	templates, err = template.ParseGlob("templates/*.html")
	if err != nil {
		log.Fatalf("Failed to load templates: %v", err)
	}

	// Setup routes
	http.HandleFunc("/", authMiddleware(handleLanding))
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/health", handleHealth)

	// Proxy routes for services with auth headers
	http.HandleFunc("/weather", proxyWithAuth("http://localhost:8081/"))
	http.HandleFunc("/weather/", proxyWithAuth("http://localhost:8081/"))
	http.HandleFunc("/api/", proxyWithAuth("http://localhost:8081/"))
	http.HandleFunc("/static/", proxyWithAuth("http://localhost:8081/"))

	// Start cleanup of expired sessions
	go cleanupSessions()

	// Start server
	addr := fmt.Sprintf(":%d", config.Server.Port)
	log.Printf("🏠 Home Services Hub starting on %s", addr)
	if config.Auth.Enabled {
		log.Printf("🔒 Authentication enabled")
	}
	log.Fatal(http.ListenAndServe(addr, nil))
}

func loadConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, &config)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func handleLanding(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	// Get user role from session
	userRole := "admin" // Default if auth disabled
	if config.Auth.Enabled {
		cookie, err := r.Cookie("session_token")
		if err == nil {
			sessionsMux.RLock()
			session, exists := sessions[cookie.Value]
			sessionsMux.RUnlock()
			if exists {
				userRole = session.Role
			}
		}
	}

	// Filter services based on user role
	type ServiceView struct {
		Name        string
		Description string
		Icon        string
		Path        string
		Enabled     bool
	}

	type PageData struct {
		Services []ServiceView
		Username string
		Role     string
	}

	var filteredServices []ServiceView
	for _, service := range config.Services {
		if !service.Enabled {
			// Show disabled services to all users
			filteredServices = append(filteredServices, ServiceView{
				Name:        service.Name,
				Description: service.Description,
				Icon:        service.Icon,
				Path:        service.Path,
				Enabled:     false,
			})
			continue
		}

		// Check if user role is allowed
		allowed := len(service.AllowedRoles) == 0 // If no roles specified, allow all
		for _, allowedRole := range service.AllowedRoles {
			if allowedRole == userRole {
				allowed = true
				break
			}
		}

		if allowed {
			filteredServices = append(filteredServices, ServiceView{
				Name:        service.Name,
				Description: service.Description,
				Icon:        service.Icon,
				Path:        service.Path,
				Enabled:     true,
			})
		}
	}

	// Get username from session
	username := ""
	if config.Auth.Enabled {
		cookie, _ := r.Cookie("session_token")
		if cookie != nil {
			sessionsMux.RLock()
			session, exists := sessions[cookie.Value]
			sessionsMux.RUnlock()
			if exists {
				username = session.Username
			}
		}
	}

	data := PageData{
		Services: filteredServices,
		Username: username,
		Role:     userRole,
	}

	if err := templates.ExecuteTemplate(w, "index.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Printf("Template error: %v", err)
	}
}

// Authentication middleware
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !config.Auth.Enabled {
			next(w, r)
			return
		}

		cookie, err := r.Cookie("session_token")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		sessionsMux.RLock()
		session, exists := sessions[cookie.Value]
		sessionsMux.RUnlock()

		if !exists || session.ExpiresAt.Before(time.Now()) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next(w, r)
	}
}

// Handle login page and form submission
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html")
		if err := templates.ExecuteTemplate(w, "login.html", nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Validate credentials
		var userRole string
		authenticated := false
		for _, user := range config.Auth.Users {
			if user.Username == username {
				err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
				if err == nil {
					authenticated = true
					userRole = user.Role
					break
				}
			}
		}

		if !authenticated {
			w.Header().Set("Content-Type", "text/html")
			templates.ExecuteTemplate(w, "login.html", map[string]string{"Error": "Invalid credentials"})
			return
		}

		// Create session
		sessionToken := generateSessionToken()
		expiresAt := time.Now().Add(24 * time.Hour)

		sessionsMux.Lock()
		sessions[sessionToken] = &Session{
			Username:  username,
			Role:      userRole,
			ExpiresAt: expiresAt,
		}
		sessionsMux.Unlock()

		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    sessionToken,
			Expires:  expiresAt,
			HttpOnly: true,
			Secure:   true, // Required for HTTPS
			SameSite: http.SameSiteLaxMode,
			Path:     "/",
		})

		log.Printf("User logged in: %s", username)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
}

// Handle logout
func handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err == nil {
		sessionsMux.Lock()
		delete(sessions, cookie.Value)
		sessionsMux.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		HttpOnly: true,
		Path:     "/",
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// Generate random session token
func generateSessionToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// Cleanup expired sessions periodically
func cleanupSessions() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		sessionsMux.Lock()
		for token, session := range sessions {
			if session.ExpiresAt.Before(time.Now()) {
				delete(sessions, token)
			}
		}
		sessionsMux.Unlock()
	}
}

// Proxy requests to backend services with auth headers
func proxyWithAuth(targetURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get user info from session
		username := ""
		role := "guest" // Default to guest if not authenticated

		// Allow SSE connections through without authentication check
		// The page that creates the EventSource is already protected
		if r.URL.Path == "/api/stream" || r.Header.Get("Accept") == "text/event-stream" {
			// Pass through to backend without auth headers
			targetPath := strings.TrimPrefix(r.URL.Path, "/weather")
			if targetPath == "" {
				targetPath = "/"
			}
			proxyURL := targetURL + strings.TrimPrefix(targetPath, "/")
			if r.URL.RawQuery != "" {
				proxyURL += "?" + r.URL.RawQuery
			}

			proxyReq, err := http.NewRequest(r.Method, proxyURL, r.Body)
			if err != nil {
				http.Error(w, "Failed to create proxy request", http.StatusInternalServerError)
				return
			}

			// Copy headers
			for key, values := range r.Header {
				for _, value := range values {
					proxyReq.Header.Add(key, value)
				}
			}

			// Execute the proxy request
			client := &http.Client{
				Timeout: 0, // No timeout for SSE
			}
			resp, err := client.Do(proxyReq)
			if err != nil {
				http.Error(w, "Failed to proxy request", http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()

			// Copy response headers
			for key, values := range resp.Header {
				for _, value := range values {
					w.Header().Add(key, value)
				}
			}
			w.WriteHeader(resp.StatusCode)

			// Stream the response
			io.Copy(w, resp.Body)
			return
		}

		if config.Auth.Enabled {
			cookie, err := r.Cookie("session_token")
			if err != nil {
				// No session, redirect to login
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			sessionsMux.RLock()
			session, exists := sessions[cookie.Value]
			sessionsMux.RUnlock()

			if !exists || session.ExpiresAt.Before(time.Now()) {
				// Invalid or expired session
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			username = session.Username
			role = session.Role
		}

		// Build the target URL
		targetPath := strings.TrimPrefix(r.URL.Path, "/weather")
		if targetPath == "" {
			targetPath = "/"
		}
		proxyURL := targetURL + strings.TrimPrefix(targetPath, "/")
		if r.URL.RawQuery != "" {
			proxyURL += "?" + r.URL.RawQuery
		}

		// Create the proxy request
		proxyReq, err := http.NewRequest(r.Method, proxyURL, r.Body)
		if err != nil {
			http.Error(w, "Failed to create proxy request", http.StatusInternalServerError)
			log.Printf("Proxy error: %v", err)
			return
		}

		// Copy headers
		for key, values := range r.Header {
			for _, value := range values {
				proxyReq.Header.Add(key, value)
			}
		}

		// Add auth headers for the backend service
		proxyReq.Header.Set("X-Hub-User", username)
		proxyReq.Header.Set("X-Hub-Role", role)
		proxyReq.Header.Set("X-Hub-Authenticated", "true")

		log.Printf("Proxying to %s - User: %s, Role: %s", proxyURL, username, role)

		// Send the request
		client := &http.Client{
			Timeout: 30 * time.Second,
		}
		resp, err := client.Do(proxyReq)
		if err != nil {
			http.Error(w, "Failed to reach backend service", http.StatusBadGateway)
			log.Printf("Proxy error: %v", err)
			return
		}
		defer resp.Body.Close()

		// Copy response headers
		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}

		// Copy status code
		w.WriteHeader(resp.StatusCode)

		// Copy response body
		io.Copy(w, resp.Body)
	}
}
