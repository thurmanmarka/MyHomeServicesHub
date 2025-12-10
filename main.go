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
	http.HandleFunc("/change-password", authMiddleware(handleChangePassword))
	http.HandleFunc("/admin/users", adminOnly(handleUserManagement))
	http.HandleFunc("/admin/users/add", adminOnly(handleAddUser))
	http.HandleFunc("/admin/users/delete", adminOnly(handleDeleteUser))
	http.HandleFunc("/admin/users/update", adminOnly(handleUpdateUser))
	http.HandleFunc("/health", handleHealth)

	// Proxy routes for services with auth headers
	http.HandleFunc("/weather", proxyWithAuth("http://localhost:8081/"))
	http.HandleFunc("/weather/", proxyWithAuth("http://localhost:8081/"))
	http.HandleFunc("/api/", proxyWithAuth("http://localhost:8081/"))
	http.HandleFunc("/static/", proxyWithAuth("http://localhost:8081/"))

	// SNMP Monitor routes
	http.HandleFunc("/snmp", proxyWithAuth("http://localhost:8082/"))
	http.HandleFunc("/snmp/", proxyWithAuth("http://localhost:8082/"))

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

func saveConfig(path string) error {
	data, err := yaml.Marshal(&config)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
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

// Admin-only middleware
func adminOnly(next http.HandlerFunc) http.HandlerFunc {
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

		if session.Role != "admin" {
			http.Error(w, "Forbidden: Admin access required", http.StatusForbidden)
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

		// Detect if we're behind HTTPS proxy (X-Forwarded-Proto header)
		isHTTPS := r.Header.Get("X-Forwarded-Proto") == "https" || r.TLS != nil

		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    sessionToken,
			Expires:  expiresAt,
			HttpOnly: true,
			Secure:   isHTTPS, // Secure only for HTTPS
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

// Handle change password
func handleChangePassword(w http.ResponseWriter, r *http.Request) {
	// Get current user from session
	cookie, err := r.Cookie("session_token")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	sessionsMux.RLock()
	session, exists := sessions[cookie.Value]
	sessionsMux.RUnlock()

	if !exists {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html")
		data := map[string]string{
			"Username": session.Username,
		}
		if err := templates.ExecuteTemplate(w, "change-password.html", data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	if r.Method == "POST" {
		currentPassword := r.FormValue("current_password")
		newPassword := r.FormValue("new_password")
		confirmPassword := r.FormValue("confirm_password")

		// Validate inputs
		if newPassword != confirmPassword {
			w.Header().Set("Content-Type", "text/html")
			data := map[string]string{
				"Username": session.Username,
				"Error":    "New passwords do not match",
			}
			templates.ExecuteTemplate(w, "change-password.html", data)
			return
		}

		if len(newPassword) < 8 {
			w.Header().Set("Content-Type", "text/html")
			data := map[string]string{
				"Username": session.Username,
				"Error":    "New password must be at least 8 characters",
			}
			templates.ExecuteTemplate(w, "change-password.html", data)
			return
		}

		// Verify current password
		var userIndex int
		var userFound bool
		for i, user := range config.Auth.Users {
			if user.Username == session.Username {
				err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(currentPassword))
				if err == nil {
					userIndex = i
					userFound = true
					break
				}
			}
		}

		if !userFound {
			w.Header().Set("Content-Type", "text/html")
			data := map[string]string{
				"Username": session.Username,
				"Error":    "Current password is incorrect",
			}
			templates.ExecuteTemplate(w, "change-password.html", data)
			return
		}

		// Hash new password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Failed to hash password", http.StatusInternalServerError)
			return
		}

		// Update config in memory
		config.Auth.Users[userIndex].Password = string(hashedPassword)

		// Save to config file
		if err := saveConfig("config.yaml"); err != nil {
			log.Printf("Failed to save config: %v", err)
			http.Error(w, "Failed to save new password", http.StatusInternalServerError)
			return
		}

		log.Printf("Password changed for user: %s", session.Username)

		// Show success page
		w.Header().Set("Content-Type", "text/html")
		data := map[string]string{
			"Username": session.Username,
			"Success":  "Password changed successfully",
		}
		templates.ExecuteTemplate(w, "change-password.html", data)
		return
	}
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
		var targetPath string
		if strings.HasPrefix(r.URL.Path, "/snmp/") {
			targetPath = strings.TrimPrefix(r.URL.Path, "/snmp")
		} else if strings.HasPrefix(r.URL.Path, "/weather/") {
			targetPath = strings.TrimPrefix(r.URL.Path, "/weather")
		} else {
			targetPath = r.URL.Path
		}
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
		isJS := strings.HasSuffix(r.URL.Path, ".js") || strings.Contains(r.URL.Path, ".js?")
		for key, values := range resp.Header {
			// If JS file, override Content-Type
			if isJS && strings.ToLower(key) == "content-type" {
				w.Header().Set("Content-Type", "application/javascript")
				continue
			}
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		// If JS file and backend didn't set Content-Type, set it
		if isJS && w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "application/javascript")
		}

		// Copy status code
		w.WriteHeader(resp.StatusCode)

		// Copy response body
		io.Copy(w, resp.Body)
	}
}

// User management handlers

func handleUserManagement(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	cookie, _ := r.Cookie("session_token")
	sessionsMux.RLock()
	session, _ := sessions[cookie.Value]
	sessionsMux.RUnlock()

	data := struct {
		Username string
		Users    []struct {
			Username string
			Role     string
		}
	}{
		Username: session.Username,
	}

	// Build user list (exclude passwords)
	for _, user := range config.Auth.Users {
		data.Users = append(data.Users, struct {
			Username string
			Role     string
		}{
			Username: user.Username,
			Role:     user.Role,
		})
	}

	if err := templates.ExecuteTemplate(w, "user-management.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func handleAddUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	role := r.FormValue("role")

	// Validate inputs
	if username == "" || password == "" || role == "" {
		http.Error(w, "All fields required", http.StatusBadRequest)
		return
	}

	if role != "admin" && role != "user" && role != "guest" {
		http.Error(w, "Invalid role", http.StatusBadRequest)
		return
	}

	// Check if user already exists
	for _, user := range config.Auth.Users {
		if user.Username == username {
			http.Error(w, "User already exists", http.StatusConflict)
			return
		}
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// Add user to config
	config.Auth.Users = append(config.Auth.Users, struct {
		Username string `yaml:"username"`
		Password string `yaml:"password"`
		Role     string `yaml:"role"`
	}{
		Username: username,
		Password: string(hashedPassword),
		Role:     role,
	})

	// Save config
	if err := saveConfig("config.yaml"); err != nil {
		log.Printf("Failed to save config: %v", err)
		http.Error(w, "Failed to save user", http.StatusInternalServerError)
		return
	}

	log.Printf("User added: %s (role: %s)", username, role)
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

func handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")

	// Don't allow deleting yourself
	cookie, _ := r.Cookie("session_token")
	sessionsMux.RLock()
	session, _ := sessions[cookie.Value]
	sessionsMux.RUnlock()

	if session.Username == username {
		http.Error(w, "Cannot delete yourself", http.StatusBadRequest)
		return
	}

	// Don't allow deleting protected users
	if username == "admin" || username == "guest" {
		http.Error(w, "Cannot delete protected user", http.StatusBadRequest)
		return
	} // Find and remove user
	found := false
	newUsers := []struct {
		Username string `yaml:"username"`
		Password string `yaml:"password"`
		Role     string `yaml:"role"`
	}{}

	for _, user := range config.Auth.Users {
		if user.Username != username {
			newUsers = append(newUsers, user)
		} else {
			found = true
		}
	}

	if !found {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	config.Auth.Users = newUsers

	// Save config
	if err := saveConfig("config.yaml"); err != nil {
		log.Printf("Failed to save config: %v", err)
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	log.Printf("User deleted: %s", username)
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

func handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	newRole := r.FormValue("role")

	// Don't allow changing protected users' roles
	if username == "admin" || username == "guest" {
		http.Error(w, "Cannot modify protected user", http.StatusBadRequest)
		return
	}

	if newRole != "admin" && newRole != "user" && newRole != "guest" {
		http.Error(w, "Invalid role", http.StatusBadRequest)
		return
	} // Find and update user
	found := false
	for i, user := range config.Auth.Users {
		if user.Username == username {
			config.Auth.Users[i].Role = newRole
			found = true
			break
		}
	}

	if !found {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Save config
	if err := saveConfig("config.yaml"); err != nil {
		log.Printf("Failed to save config: %v", err)
		http.Error(w, "Failed to update user", http.StatusInternalServerError)
		return
	}

	log.Printf("User updated: %s -> role: %s", username, newRole)
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}
