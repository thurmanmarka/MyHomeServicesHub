package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

type ConfigUser struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"` // bcrypt hash
	Role     string `yaml:"role"`
}

type Config struct {
	Server struct {
		Port int `yaml:"port"`
	} `yaml:"server"`
	Auth struct {
		Enabled       bool   `yaml:"enabled"`
		SessionSecret string `yaml:"session_secret"`
		// Only used when the database is disabled, and imported into an
		// empty database on first start.
		Users []ConfigUser `yaml:"users"`
	} `yaml:"auth"`
	Database struct {
		// When disabled, users stay in this file and sessions in memory
		Enabled  bool   `yaml:"enabled"`
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		Name     string `yaml:"name"`
		User     string `yaml:"user"`
		Password string `yaml:"password"`
	} `yaml:"database"`
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

func main() {
	// Load configuration
	if err := loadConfig("config.yaml"); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Users and sessions live in MariaDB, or in config.yaml and memory
	if config.Database.Enabled {
		store, err := openSQLStore()
		if err != nil {
			log.Fatalf("Failed to open database: %v", err)
		}
		if err := store.importConfigUsers(); err != nil {
			log.Fatalf("Failed to import users: %v", err)
		}
		auth = store
		log.Printf("🗄️  Using MariaDB database %s on %s:%d", config.Database.Name, config.Database.Host, config.Database.Port)
	} else {
		auth = newConfigStore("config.yaml")
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

	// MyWatchfulWoo-Woos routes
	http.HandleFunc("/woo", proxyWithAuth("http://localhost:8083/"))
	http.HandleFunc("/woo/", proxyWithAuth("http://localhost:8083/"))

	// SNMP Monitor routes
	http.HandleFunc("/snmp", proxyWithAuth("http://localhost:8082/"))
	http.HandleFunc("/snmp/", proxyWithAuth("http://localhost:8082/"))

	// MyWifiControl routes
	http.HandleFunc("/wifi", proxyWithAuth("http://localhost:8084/"))
	http.HandleFunc("/wifi/", proxyWithAuth("http://localhost:8084/"))

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
	if err := yaml.Unmarshal(data, &config); err != nil {
		return err
	}
	if config.Database.Host == "" {
		config.Database.Host = "127.0.0.1"
	}
	if config.Database.Port == 0 {
		config.Database.Port = 3306
	}
	if config.Database.Name == "" {
		config.Database.Name = "hub_db"
	}
	if config.Database.User == "" {
		config.Database.User = "hub_app"
	}
	return nil
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
	w.Write([]byte(`{"status": "ok"}`))
}

func handleLanding(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	// Get user from session
	userRole := "admin" // Default if auth disabled
	username := ""
	if config.Auth.Enabled {
		if session := currentSession(r); session != nil {
			userRole = session.Role
			username = session.Username
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

		if currentSession(r) == nil {
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

		session := currentSession(r)
		if session == nil {
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
		ip, userAgent := clientIP(r), r.UserAgent()
		user, found, err := auth.FindUser(username)
		if err != nil {
			log.Printf("Login lookup failed: %v", err)
			http.Error(w, "Login is unavailable right now", http.StatusServiceUnavailable)
			return
		}
		authenticated := found && bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) == nil
		auth.RecordLogin(username, authenticated, ip, userAgent)

		if !authenticated {
			w.Header().Set("Content-Type", "text/html")
			templates.ExecuteTemplate(w, "login.html", map[string]string{"Error": "Invalid credentials"})
			return
		}

		// Create session
		sessionToken := generateSessionToken()
		expiresAt := time.Now().Add(24 * time.Hour)

		if err := auth.CreateSession(sessionToken, Session{
			Username:  username,
			Role:      user.Role,
			ExpiresAt: expiresAt,
		}, ip, userAgent); err != nil {
			log.Printf("Failed to create session for %s: %v", username, err)
			http.Error(w, "Login is unavailable right now", http.StatusServiceUnavailable)
			return
		}

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
		auth.DeleteSession(cookie.Value)
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
	expectJSON := strings.Contains(r.Header.Get("Accept"), "application/json")

	// Get current user from session
	session := currentSession(r)
	if session == nil {
		if expectJSON {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": "session expired"})
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if session.Role == "guest" {
		if expectJSON {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": "Guest account cannot change password"})
			return
		}
		http.Error(w, "Guest account cannot change password", http.StatusForbidden)
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
			if expectJSON {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": "New passwords do not match"})
				return
			}
			w.Header().Set("Content-Type", "text/html")
			data := map[string]string{
				"Username": session.Username,
				"Error":    "New passwords do not match",
			}
			templates.ExecuteTemplate(w, "change-password.html", data)
			return
		}

		if len(newPassword) < 8 {
			if expectJSON {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": "New password must be at least 8 characters"})
				return
			}
			w.Header().Set("Content-Type", "text/html")
			data := map[string]string{
				"Username": session.Username,
				"Error":    "New password must be at least 8 characters",
			}
			templates.ExecuteTemplate(w, "change-password.html", data)
			return
		}

		// Verify current password
		user, found, err := auth.FindUser(session.Username)
		if err != nil {
			log.Printf("User lookup failed: %v", err)
		}
		if !found || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(currentPassword)) != nil {
			if expectJSON {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": "Current password is incorrect"})
				return
			}
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
			if expectJSON {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": "Failed to hash password"})
				return
			}
			http.Error(w, "Failed to hash password", http.StatusInternalServerError)
			return
		}

		if err := auth.SetPassword(session.Username, string(hashedPassword)); err != nil {
			log.Printf("Failed to save new password: %v", err)
			if expectJSON {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": "Failed to save new password"})
				return
			}
			http.Error(w, "Failed to save new password", http.StatusInternalServerError)
			return
		}

		log.Printf("Password changed for user: %s", session.Username)
		auth.Audit(session.Username, "password_change", session.Username, "")

		if expectJSON {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}

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
		auth.Cleanup()
	}
}

// serviceBasePath maps a proxied request path to the service path it belongs to.
// The weather app is also served from /api/ and /static/.
func serviceBasePath(path string) string {
	if strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/static/") {
		return "/weather"
	}
	if i := strings.Index(path[1:], "/"); i >= 0 {
		return path[:i+1]
	}
	return path
}

// canAccessService reports whether role may use the service that owns path,
// based on the service's allowed_roles in config.yaml. An empty list allows
// everyone. Paths with no matching service entry are admin-only.
func canAccessService(path, role string) bool {
	base := serviceBasePath(path)
	for _, service := range config.Services {
		if service.Path != base {
			continue
		}
		if len(service.AllowedRoles) == 0 {
			return true
		}
		for _, allowed := range service.AllowedRoles {
			if allowed == role {
				return true
			}
		}
		return false
	}
	return role == "admin"
}

// Proxy requests to backend services with auth headers
func proxyWithAuth(targetURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get user info from session
		username := ""
		role := "guest" // Default to guest if not authenticated

		// Allow the weather app's SSE stream through without authentication check.
		// The page that creates the EventSource is already protected. This is
		// limited to weather paths so the header can't be used to skip auth on
		// other services.
		isSSE := r.URL.Path == "/api/stream" || r.Header.Get("Accept") == "text/event-stream"
		if isSSE && serviceBasePath(r.URL.Path) == "/weather" {
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

			// Copy headers, but never let a client supply its own identity
			for key, values := range r.Header {
				for _, value := range values {
					proxyReq.Header.Add(key, value)
				}
			}
			proxyReq.Header.Del("X-Hub-User")
			proxyReq.Header.Del("X-Hub-Role")
			proxyReq.Header.Del("X-Hub-Authenticated")

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
			session := currentSession(r)
			if session == nil {
				// No valid session, redirect to login
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			username = session.Username
			role = session.Role

			// Enforce the service's allowed_roles, not just hide its tile
			if !canAccessService(r.URL.Path, role) {
				log.Printf("Denied %s (role %s) access to %s", username, role, r.URL.Path)
				http.Error(w, "Forbidden: your account does not have access to this service", http.StatusForbidden)
				return
			}
		}

		// Build the target URL
		var targetPath string
		switch {
		case strings.HasPrefix(r.URL.Path, "/snmp/") || r.URL.Path == "/snmp":
			targetPath = strings.TrimPrefix(r.URL.Path, "/snmp")
		case strings.HasPrefix(r.URL.Path, "/weather/") || r.URL.Path == "/weather":
			targetPath = strings.TrimPrefix(r.URL.Path, "/weather")
		case strings.HasPrefix(r.URL.Path, "/woo/") || r.URL.Path == "/woo":
			targetPath = strings.TrimPrefix(r.URL.Path, "/woo")
		case strings.HasPrefix(r.URL.Path, "/wifi/") || r.URL.Path == "/wifi":
			targetPath = strings.TrimPrefix(r.URL.Path, "/wifi")
		default:
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

// actor names who made a change, for the audit log. With auth disabled there
// is no session, so changes are attributed to "admin".
func actor(r *http.Request) string {
	if session := currentSession(r); session != nil {
		return session.Username
	}
	return "admin"
}

func handleUserManagement(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	users, err := auth.ListUsers()
	if err != nil {
		log.Printf("Failed to list users: %v", err)
		http.Error(w, "Failed to load users", http.StatusInternalServerError)
		return
	}

	data := struct {
		Username   string
		Users      []User
		HasHistory bool
		Logins     []LoginEvent
		Audit      []AuditEvent
	}{
		Username:   actor(r),
		Users:      users,
		HasHistory: auth.HasHistory(),
	}
	if data.HasHistory {
		if data.Logins, err = auth.RecentLogins(25); err != nil {
			log.Printf("Failed to load login history: %v", err)
		}
		if data.Audit, err = auth.RecentAudit(25); err != nil {
			log.Printf("Failed to load audit log: %v", err)
		}
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

	if len(username) > 64 {
		http.Error(w, "Username must be at most 64 characters", http.StatusBadRequest)
		return
	}

	if role != "admin" && role != "user" && role != "guest" {
		http.Error(w, "Invalid role", http.StatusBadRequest)
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	err = auth.AddUser(User{Username: username, PasswordHash: string(hashedPassword), Role: role})
	if errors.Is(err, ErrUserExists) {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}
	if err != nil {
		log.Printf("Failed to add user: %v", err)
		http.Error(w, "Failed to save user", http.StatusInternalServerError)
		return
	}

	log.Printf("User added: %s (role: %s)", username, role)
	auth.Audit(actor(r), "user_add", username, "role "+role)
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

func handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")

	// Don't allow deleting yourself
	if actor(r) == username {
		http.Error(w, "Cannot delete yourself", http.StatusBadRequest)
		return
	}

	// Don't allow deleting protected users
	if username == "admin" || username == "guest" {
		http.Error(w, "Cannot delete protected user", http.StatusBadRequest)
		return
	}

	// Deleting a user also ends their sessions
	err := auth.DeleteUser(username)
	if errors.Is(err, ErrUserNotFound) {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("Failed to delete user: %v", err)
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	log.Printf("User deleted: %s", username)
	auth.Audit(actor(r), "user_delete", username, "")
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
	}

	old, found, err := auth.FindUser(username)
	if err == nil && !found {
		err = ErrUserNotFound
	}
	if err == nil {
		err = auth.SetRole(username, newRole)
	}
	if errors.Is(err, ErrUserNotFound) {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("Failed to update user: %v", err)
		http.Error(w, "Failed to update user", http.StatusInternalServerError)
		return
	}

	// Takes effect on the user's next request; no need to log in again
	log.Printf("User updated: %s -> role: %s", username, newRole)
	auth.Audit(actor(r), "role_change", username, old.Role+" → "+newRole)
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}
