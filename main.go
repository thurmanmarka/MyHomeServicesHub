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
	"net"
	"net/http"
	"os"
	"strconv"
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
		// Address to listen on. The default, 127.0.0.1, lets only nginx on
		// this machine reach the hub; "0.0.0.0" listens on every interface.
		Bind string `yaml:"bind"`
		Port int    `yaml:"port"`
	} `yaml:"server"`
	Auth struct {
		Enabled       bool   `yaml:"enabled"`
		SessionSecret string `yaml:"session_secret"`
		SessionHours  int    `yaml:"session_hours"` // longest a login lasts (default 24)
		IdleMinutes   int    `yaml:"idle_minutes"`  // sign out after this long unused (default 120)
		// Accounts that may only be used from the home network
		LocalOnlyUsers []string `yaml:"local_only_users"`
		// What counts as the home network (CIDRs). Default: private addresses
		// (10.x, 172.16-31.x, 192.168.x) and this machine.
		LocalNetworks []string `yaml:"local_networks"`
		// Failed logins allowed within window_minutes before that IP or
		// account is refused for lockout_minutes
		LoginLimits struct {
			PerIP          int `yaml:"per_ip"`   // default 10
			PerUser        int `yaml:"per_user"` // default 20
			WindowMinutes  int `yaml:"window_minutes"`
			LockoutMinutes int `yaml:"lockout_minutes"`
		} `yaml:"login_limits"`
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
	LastSeen  time.Time
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
	l := config.Auth.LoginLimits
	limiter = newLoginLimiter(l.PerIP, l.PerUser,
		time.Duration(l.WindowMinutes)*time.Minute, time.Duration(l.LockoutMinutes)*time.Minute)

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
	addr := net.JoinHostPort(config.Server.Bind, strconv.Itoa(config.Server.Port))
	log.Printf("🏠 Home Services Hub starting on %s", addr)
	if config.Auth.Enabled {
		log.Printf("🔒 Authentication enabled")
	}
	server := &http.Server{
		Addr:    addr,
		Handler: secureHeaders(http.DefaultServeMux),
		// No overall timeouts: the weather stream stays open for hours
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
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
	if config.Server.Bind == "" {
		config.Server.Bind = "127.0.0.1"
	}
	if config.Auth.SessionHours <= 0 {
		config.Auth.SessionHours = 24
	}
	if config.Auth.IdleMinutes <= 0 {
		config.Auth.IdleMinutes = 120
	}
	localNets = nil
	for _, cidr := range config.Auth.LocalNetworks {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("auth.local_networks: %w", err)
		}
		localNets = append(localNets, n)
	}
	limits := &config.Auth.LoginLimits
	if limits.PerIP <= 0 {
		limits.PerIP = 10
	}
	if limits.PerUser <= 0 {
		limits.PerUser = 20
	}
	if limits.WindowMinutes <= 0 {
		limits.WindowMinutes = 15
	}
	if limits.LockoutMinutes <= 0 {
		limits.LockoutMinutes = 15
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
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		username := r.FormValue("username")
		password := r.FormValue("password")
		ip, userAgent := clientIP(r), r.UserAgent()

		// Refuse without checking the password while the IP or account is locked out
		if wait := limiter.Blocked(ip, username); wait > 0 {
			log.Printf("Refused login for %q from %s: locked out for %s more", username, ip, wait.Round(time.Second))
			showLoginError(w, http.StatusTooManyRequests,
				fmt.Sprintf("Too many failed sign-ins. Try again in %d min.", int(wait.Minutes())+1))
			return
		}

		// Home-network-only accounts are refused elsewhere without checking
		// the password, so their password can't be guessed from outside
		if !allowedFrom(username, ip) {
			log.Printf("Refused login for %q from %s: account is limited to the home network", username, ip)
			auth.RecordLogin(username, false, ip, userAgent)
			showLoginError(w, http.StatusUnauthorized, "Invalid credentials")
			return
		}

		// Validate credentials
		user, found, err := auth.FindUser(username)
		if err != nil {
			log.Printf("Login lookup failed: %v", err)
			http.Error(w, "Login is unavailable right now", http.StatusServiceUnavailable)
			return
		}
		// Unknown usernames are checked against a dummy hash, so how long the
		// answer takes doesn't reveal which usernames exist
		hash := dummyPasswordHash
		if found {
			hash = user.PasswordHash
		}
		authenticated := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil && found
		auth.RecordLogin(username, authenticated, ip, userAgent)

		if !authenticated {
			log.Printf("Failed login for %q from %s", username, ip)
			for _, lock := range limiter.Failure(ip, username, found) {
				log.Printf("Locked out %s %s for %d minutes after repeated failed logins",
					lock.Kind, lock.Value, config.Auth.LoginLimits.LockoutMinutes)
				auth.Audit("hub", "login_lockout", lock.Value, lock.Kind)
			}
			showLoginError(w, http.StatusUnauthorized, "Invalid credentials")
			return
		}
		limiter.Success(ip, username)

		// Create session
		sessionToken := generateSessionToken()
		expiresAt := time.Now().Add(sessionLifetime())

		if err := auth.CreateSession(sessionToken, Session{
			Username:  username,
			Role:      user.Role,
			ExpiresAt: expiresAt,
		}, ip, userAgent); err != nil {
			log.Printf("Failed to create session for %s: %v", username, err)
			http.Error(w, "Login is unavailable right now", http.StatusServiceUnavailable)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    sessionToken,
			Expires:  expiresAt,
			HttpOnly: true,
			Secure:   isHTTPS(r), // Secure only for HTTPS
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
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func showLoginError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)
	templates.ExecuteTemplate(w, "login.html", map[string]string{"Error": message})
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

		if len(newPassword) < minPasswordLength {
			msg := fmt.Sprintf("New password must be at least %d characters", minPasswordLength)
			if expectJSON {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": msg})
				return
			}
			w.Header().Set("Content-Type", "text/html")
			data := map[string]string{
				"Username": session.Username,
				"Error":    msg,
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

		// Sign out every other browser, in case the old password was stolen
		keep := ""
		if cookie, err := r.Cookie("session_token"); err == nil {
			keep = cookie.Value
		}
		if err := auth.DeleteUserSessions(session.Username, keep); err != nil {
			log.Printf("Failed to end other sessions for %s: %v", session.Username, err)
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
		limiter.Prune()
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

		// The weather app's live stream stays open, so it is proxied without a
		// timeout. The browser sends the session cookie with it like any other
		// request, so it needs a login too.
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

			// Copy response headers (the service's own replace the hub's defaults)
			for key, values := range resp.Header {
				w.Header()[key] = values
			}
			w.WriteHeader(resp.StatusCode)

			// Stream the response
			io.Copy(w, resp.Body)
			return
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

		// Copy response headers (the service's own replace the hub's defaults)
		isJS := strings.HasSuffix(r.URL.Path, ".js") || strings.Contains(r.URL.Path, ".js?")
		for key, values := range resp.Header {
			// If JS file, override Content-Type
			if isJS && strings.ToLower(key) == "content-type" {
				w.Header().Set("Content-Type", "application/javascript")
				continue
			}
			w.Header()[key] = values
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

	if len(password) < minPasswordLength {
		http.Error(w, fmt.Sprintf("Password must be at least %d characters", minPasswordLength), http.StatusBadRequest)
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
