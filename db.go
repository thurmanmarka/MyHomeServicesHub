package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/go-sql-driver/mysql"
)

// sqlStore keeps users, sessions, login attempts and the audit log in MariaDB.
// All times are stored in UTC.
type sqlStore struct {
	db *sql.DB
}

var schema = []string{
	// utf8mb4_bin keeps usernames case-sensitive, as they were in config.yaml
	`CREATE TABLE IF NOT EXISTS users (
		id            INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
		username      VARCHAR(64) COLLATE utf8mb4_bin NOT NULL UNIQUE,
		password_hash VARCHAR(255) NOT NULL,
		role          VARCHAR(16)  NOT NULL,
		created_at    DATETIME NOT NULL,
		updated_at    DATETIME NOT NULL,
		last_login_at DATETIME NULL
	) ENGINE=InnoDB`,
	`CREATE TABLE IF NOT EXISTS sessions (
		token_hash CHAR(64) NOT NULL PRIMARY KEY,
		user_id    INT UNSIGNED NOT NULL,
		created_at DATETIME NOT NULL,
		expires_at DATETIME NOT NULL,
		last_seen_at DATETIME NULL,
		ip         VARCHAR(45)  NOT NULL DEFAULT '',
		user_agent VARCHAR(255) NOT NULL DEFAULT '',
		KEY idx_expires (expires_at),
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	) ENGINE=InnoDB`,
	`CREATE TABLE IF NOT EXISTS login_events (
		id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
		username   VARCHAR(64)  NOT NULL,
		success    BOOLEAN      NOT NULL,
		ip         VARCHAR(45)  NOT NULL DEFAULT '',
		user_agent VARCHAR(255) NOT NULL DEFAULT '',
		created_at DATETIME NOT NULL,
		KEY idx_created (created_at),
		KEY idx_user_created (username, created_at)
	) ENGINE=InnoDB`,
	`CREATE TABLE IF NOT EXISTS audit_log (
		id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
		actor      VARCHAR(64)  NOT NULL,
		action     VARCHAR(32)  NOT NULL,
		target     VARCHAR(64)  NOT NULL DEFAULT '',
		detail     VARCHAR(255) NOT NULL DEFAULT '',
		created_at DATETIME NOT NULL,
		KEY idx_created (created_at)
	) ENGINE=InnoDB`,
	// Added for the idle timeout; older sessions count from created_at
	`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_seen_at DATETIME NULL AFTER expires_at`,
}

// openSQLStore connects to MariaDB and creates any missing tables.
func openSQLStore() (*sqlStore, error) {
	c := config.Database
	mc := mysql.NewConfig()
	mc.User = c.User
	mc.Passwd = c.Password
	mc.Net = "tcp"
	mc.Addr = fmt.Sprintf("%s:%d", c.Host, c.Port)
	mc.DBName = c.Name
	mc.ParseTime = true
	// Count matched rows, not changed rows, so setting a role to its current
	// value isn't mistaken for a missing user
	mc.ClientFoundRows = true
	mc.Loc = time.UTC
	mc.Params = map[string]string{"time_zone": "'+00:00'"}

	db, err := sql.Open("mysql", mc.FormatDSN())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	db.SetConnMaxLifetime(30 * time.Minute)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("connect to %s as %s: %w", mc.Addr, c.User, err)
	}
	for _, stmt := range schema {
		if _, err := db.Exec(stmt); err != nil {
			db.Close()
			return nil, fmt.Errorf("create schema: %w", err)
		}
	}
	return &sqlStore{db: db}, nil
}

// importConfigUsers copies the users from config.yaml into an empty users
// table, keeping their bcrypt hashes, so nobody's password changes.
func (s *sqlStore) importConfigUsers() error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		if len(config.Auth.Users) > 0 {
			log.Printf("Users come from the database; auth.users in config.yaml is ignored")
		}
		return nil
	}
	for _, u := range config.Auth.Users {
		if err := s.AddUser(User{Username: u.Username, PasswordHash: u.Password, Role: u.Role}); err != nil {
			return fmt.Errorf("import user %s: %w", u.Username, err)
		}
	}
	log.Printf("Imported %d users from config.yaml into the database", len(config.Auth.Users))
	return nil
}

func (s *sqlStore) FindUser(username string) (User, bool, error) {
	var u User
	var last sql.NullTime
	err := s.db.QueryRow(`SELECT username, password_hash, role, last_login_at FROM users WHERE username = ?`,
		username).Scan(&u.Username, &u.PasswordHash, &u.Role, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, err
	}
	if last.Valid {
		t := last.Time.Local()
		u.LastLogin = &t
	}
	return u, true, nil
}

func (s *sqlStore) ListUsers() ([]User, error) {
	rows, err := s.db.Query(`SELECT username, role, last_login_at FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		var last sql.NullTime
		if err := rows.Scan(&u.Username, &u.Role, &last); err != nil {
			return nil, err
		}
		if last.Valid {
			t := last.Time.Local()
			u.LastLogin = &t
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *sqlStore) AddUser(u User) error {
	now := time.Now().UTC()
	_, err := s.db.Exec(`INSERT INTO users (username, password_hash, role, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)`, u.Username, u.PasswordHash, u.Role, now, now)
	var me *mysql.MySQLError
	if errors.As(err, &me) && me.Number == 1062 { // duplicate key
		return ErrUserExists
	}
	return err
}

func (s *sqlStore) DeleteUser(username string) error {
	// The user's sessions go with it (ON DELETE CASCADE)
	return s.affectOne(`DELETE FROM users WHERE username = ?`, username)
}

func (s *sqlStore) SetRole(username, role string) error {
	return s.affectOne(`UPDATE users SET role = ?, updated_at = ? WHERE username = ?`,
		role, time.Now().UTC(), username)
}

func (s *sqlStore) SetPassword(username, hash string) error {
	return s.affectOne(`UPDATE users SET password_hash = ?, updated_at = ? WHERE username = ?`,
		hash, time.Now().UTC(), username)
}

// affectOne runs a statement that should change exactly one user.
func (s *sqlStore) affectOne(query string, args ...any) error {
	res, err := s.db.Exec(query, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (s *sqlStore) CreateSession(token string, sess Session, ip, userAgent string) error {
	if len(userAgent) > 255 {
		userAgent = userAgent[:255]
	}
	now := time.Now().UTC()
	_, err := s.db.Exec(`INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_seen_at, ip, user_agent)
		SELECT ?, id, ?, ?, ?, ?, ? FROM users WHERE username = ?`,
		hashToken(token), now, sess.ExpiresAt.UTC(), now, ip, userAgent, sess.Username)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`UPDATE users SET last_login_at = ? WHERE username = ?`, now, sess.Username)
	return err
}

func (s *sqlStore) GetSession(token string) (*Session, bool) {
	var sess Session
	now := time.Now().UTC()
	tokenHash := hashToken(token)
	err := s.db.QueryRow(`SELECT u.username, u.role, s.expires_at, COALESCE(s.last_seen_at, s.created_at)
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ? AND s.expires_at > ? AND COALESCE(s.last_seen_at, s.created_at) > ?`,
		tokenHash, now, now.Add(-idleTimeout())).Scan(&sess.Username, &sess.Role, &sess.ExpiresAt, &sess.LastSeen)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			log.Printf("Session lookup failed: %v", err)
		}
		return nil, false
	}
	// To the minute is plenty for the idle timeout; no need to write on every request
	if now.Sub(sess.LastSeen) > time.Minute {
		if _, err := s.db.Exec(`UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?`, now, tokenHash); err != nil {
			log.Printf("Failed to update session: %v", err)
		}
	}
	return &sess, true
}

func (s *sqlStore) DeleteSession(token string) {
	if _, err := s.db.Exec(`DELETE FROM sessions WHERE token_hash = ?`, hashToken(token)); err != nil {
		log.Printf("Failed to delete session: %v", err)
	}
}

func (s *sqlStore) DeleteUserSessions(username, keepToken string) error {
	_, err := s.db.Exec(`DELETE s FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE u.username = ? AND s.token_hash <> ?`, username, hashToken(keepToken))
	return err
}

// Cleanup removes expired and idle sessions, and login attempts older than a year.
func (s *sqlStore) Cleanup() {
	now := time.Now().UTC()
	if _, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at < ? OR COALESCE(last_seen_at, created_at) < ?`,
		now, now.Add(-idleTimeout())); err != nil {
		log.Printf("Session cleanup failed: %v", err)
	}
	if _, err := s.db.Exec(`DELETE FROM login_events WHERE created_at < ?`, now.AddDate(-1, 0, 0)); err != nil {
		log.Printf("Login history cleanup failed: %v", err)
	}
}

func (s *sqlStore) RecordLogin(username string, success bool, ip, userAgent string) {
	if len(username) > 64 {
		username = username[:64]
	}
	if len(userAgent) > 255 {
		userAgent = userAgent[:255]
	}
	if _, err := s.db.Exec(`INSERT INTO login_events (username, success, ip, user_agent, created_at)
		VALUES (?, ?, ?, ?, ?)`, username, success, ip, userAgent, time.Now().UTC()); err != nil {
		log.Printf("Failed to record login: %v", err)
	}
}

func (s *sqlStore) Audit(actor, action, target, detail string) {
	if _, err := s.db.Exec(`INSERT INTO audit_log (actor, action, target, detail, created_at)
		VALUES (?, ?, ?, ?, ?)`, actor, action, target, detail, time.Now().UTC()); err != nil {
		log.Printf("Failed to write audit log: %v", err)
	}
}

func (s *sqlStore) HasHistory() bool { return true }

func (s *sqlStore) RecentLogins(n int) ([]LoginEvent, error) {
	rows, err := s.db.Query(`SELECT username, success, ip, user_agent, created_at
		FROM login_events ORDER BY id DESC LIMIT ?`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []LoginEvent
	for rows.Next() {
		var e LoginEvent
		if err := rows.Scan(&e.Username, &e.Success, &e.IP, &e.UserAgent, &e.At); err != nil {
			return nil, err
		}
		e.At = e.At.Local()
		events = append(events, e)
	}
	return events, rows.Err()
}

func (s *sqlStore) RecentAudit(n int) ([]AuditEvent, error) {
	rows, err := s.db.Query(`SELECT actor, action, target, detail, created_at
		FROM audit_log ORDER BY id DESC LIMIT ?`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []AuditEvent
	for rows.Next() {
		var e AuditEvent
		if err := rows.Scan(&e.Actor, &e.Action, &e.Target, &e.Detail, &e.At); err != nil {
			return nil, err
		}
		e.At = e.At.Local()
		events = append(events, e)
	}
	return events, rows.Err()
}
