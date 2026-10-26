package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// User is an account that can log in to the hub.
type User struct {
	Username     string
	PasswordHash string // bcrypt
	Role         string
	LastLogin    *time.Time
}

// LoginEvent is one login attempt, shown on the admin page.
type LoginEvent struct {
	Username  string
	Success   bool
	IP        string
	UserAgent string
	At        time.Time
}

// AuditEvent is one change made through the hub (users, roles, passwords).
type AuditEvent struct {
	Actor  string
	Action string
	Target string
	Detail string
	At     time.Time
}

var (
	ErrUserExists   = errors.New("user already exists")
	ErrUserNotFound = errors.New("user not found")
)

// AuthStore keeps users and sessions. configStore is the original behaviour
// (users in config.yaml, sessions in memory); sqlStore keeps both in MariaDB.
type AuthStore interface {
	FindUser(username string) (User, bool, error)
	ListUsers() ([]User, error)
	AddUser(u User) error
	DeleteUser(username string) error
	SetRole(username, role string) error
	SetPassword(username, hash string) error

	CreateSession(token string, s Session, ip, userAgent string) error
	// GetSession returns the session's user with their current role, or false
	// if the token is unknown or expired.
	GetSession(token string) (*Session, bool)
	DeleteSession(token string)
	Cleanup()

	RecordLogin(username string, success bool, ip, userAgent string)
	Audit(actor, action, target, detail string)
	// HasHistory reports whether RecentLogins and RecentAudit keep anything.
	HasHistory() bool
	RecentLogins(n int) ([]LoginEvent, error)
	RecentAudit(n int) ([]AuditEvent, error)
}

var auth AuthStore

// currentSession returns the logged-in session for r, or nil.
func currentSession(r *http.Request) *Session {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return nil
	}
	s, ok := auth.GetSession(cookie.Value)
	if !ok {
		return nil
	}
	return s
}

// clientIP is the browser's address. nginx passes it in X-Real-IP; the header
// is only trusted when the request came from nginx on this machine.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if real := r.Header.Get("X-Real-IP"); real != "" {
			return real
		}
	}
	return host
}

// hashToken is what the database stores instead of the session token, so a
// copy of the database can't be used to log in.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// configStore keeps users in config.yaml and sessions in memory, as the hub
// did before it had a database. Sessions are lost on restart.
type configStore struct {
	mu       sync.RWMutex
	path     string
	sessions map[string]*Session
}

func newConfigStore(path string) *configStore {
	return &configStore{path: path, sessions: make(map[string]*Session)}
}

func (c *configStore) FindUser(username string) (User, bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, u := range config.Auth.Users {
		if u.Username == username {
			return User{Username: u.Username, PasswordHash: u.Password, Role: u.Role}, true, nil
		}
	}
	return User{}, false, nil
}

func (c *configStore) ListUsers() ([]User, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	users := make([]User, 0, len(config.Auth.Users))
	for _, u := range config.Auth.Users {
		users = append(users, User{Username: u.Username, Role: u.Role})
	}
	return users, nil
}

func (c *configStore) AddUser(u User) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, existing := range config.Auth.Users {
		if existing.Username == u.Username {
			return ErrUserExists
		}
	}
	config.Auth.Users = append(config.Auth.Users, ConfigUser{Username: u.Username, Password: u.PasswordHash, Role: u.Role})
	return saveConfig(c.path)
}

func (c *configStore) DeleteUser(username string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	kept := config.Auth.Users[:0:0]
	for _, u := range config.Auth.Users {
		if u.Username != username {
			kept = append(kept, u)
		}
	}
	if len(kept) == len(config.Auth.Users) {
		return ErrUserNotFound
	}
	config.Auth.Users = kept
	for token, s := range c.sessions {
		if s.Username == username {
			delete(c.sessions, token)
		}
	}
	return saveConfig(c.path)
}

func (c *configStore) SetRole(username, role string) error {
	return c.update(username, func(u *ConfigUser) { u.Role = role })
}

func (c *configStore) SetPassword(username, hash string) error {
	return c.update(username, func(u *ConfigUser) { u.Password = hash })
}

func (c *configStore) update(username string, change func(*ConfigUser)) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range config.Auth.Users {
		if config.Auth.Users[i].Username == username {
			change(&config.Auth.Users[i])
			return saveConfig(c.path)
		}
	}
	return ErrUserNotFound
}

func (c *configStore) CreateSession(token string, s Session, ip, userAgent string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessions[token] = &s
	return nil
}

func (c *configStore) GetSession(token string) (*Session, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s, ok := c.sessions[token]
	if !ok || s.ExpiresAt.Before(time.Now()) {
		return nil, false
	}
	// Look up the current role so a role change applies straight away
	for _, u := range config.Auth.Users {
		if u.Username == s.Username {
			current := *s
			current.Role = u.Role
			return &current, true
		}
	}
	return nil, false
}

func (c *configStore) DeleteSession(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.sessions, token)
}

func (c *configStore) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for token, s := range c.sessions {
		if s.ExpiresAt.Before(time.Now()) {
			delete(c.sessions, token)
		}
	}
}

func (c *configStore) RecordLogin(username string, success bool, ip, userAgent string) {
	if !success {
		log.Printf("Failed login for %q from %s", username, ip)
	}
}

func (c *configStore) Audit(actor, action, target, detail string) {}

func (c *configStore) HasHistory() bool                         { return false }
func (c *configStore) RecentLogins(n int) ([]LoginEvent, error) { return nil, nil }
func (c *configStore) RecentAudit(n int) ([]AuditEvent, error)  { return nil, nil }
