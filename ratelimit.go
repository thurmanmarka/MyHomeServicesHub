package main

import (
	"sync"
	"time"
)

// loginLimiter slows down password guessing. It counts failed logins per
// client IP and per account, and once either reaches its limit within the
// window, refuses logins from that IP or for that account until the lockout
// ends, without checking the password. The per-account limit catches guessing
// spread over many IPs. Counts are kept in memory, so a restart clears them.
type loginLimiter struct {
	mu      sync.Mutex
	perIP   int
	perUser int
	window  time.Duration
	lockout time.Duration
	entries map[string]*attempts
	now     func() time.Time
}

type attempts struct {
	failures    []time.Time
	lockedUntil time.Time
}

// Lockout is an IP address or account that Failure just locked out.
type Lockout struct {
	Kind  string // "IP address" or "account"
	Value string
}

// With this many IPs and accounts tracked, stale entries are dropped, and if
// that isn't enough, new ones aren't tracked until it is.
const maxLimiterEntries = 10000

var limiter *loginLimiter

func newLoginLimiter(perIP, perUser int, window, lockout time.Duration) *loginLimiter {
	return &loginLimiter{
		perIP:   perIP,
		perUser: perUser,
		window:  window,
		lockout: lockout,
		entries: make(map[string]*attempts),
		now:     time.Now,
	}
}

func ipKey(ip string) string { return "ip " + ip }

func userKey(username string) string {
	if len(username) > 64 {
		username = username[:64]
	}
	return "user " + username
}

// Blocked returns how long until a login from ip for username may be tried
// again, or 0 if it may be tried now.
func (l *loginLimiter) Blocked(ip, username string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	var wait time.Duration
	for _, key := range []string{ipKey(ip), userKey(username)} {
		if a := l.entries[key]; a != nil && a.lockedUntil.After(now) {
			wait = max(wait, a.lockedUntil.Sub(now))
		}
	}
	return wait
}

// Failure records a failed login and returns what it locked out. Only
// existing accounts are counted, so made-up usernames can't fill the table.
func (l *loginLimiter) Failure(ip, username string, accountExists bool) []Lockout {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.entries) >= maxLimiterEntries {
		l.prune(now)
	}

	type counter struct {
		key   string
		limit int
		lock  Lockout
	}
	counters := []counter{{ipKey(ip), l.perIP, Lockout{"IP address", ip}}}
	if accountExists {
		counters = append(counters, counter{userKey(username), l.perUser, Lockout{"account", username}})
	}

	var locked []Lockout
	for _, c := range counters {
		a := l.entries[c.key]
		if a == nil {
			if len(l.entries) >= maxLimiterEntries {
				continue
			}
			a = &attempts{}
			l.entries[c.key] = a
		}
		a.failures = recentOnly(a.failures, now.Add(-l.window))
		a.failures = append(a.failures, now)
		if len(a.failures) >= c.limit {
			a.lockedUntil = now.Add(l.lockout)
			a.failures = nil
			locked = append(locked, c.lock)
		}
	}
	return locked
}

// Success clears the failed attempts of the IP and account that just logged in.
func (l *loginLimiter) Success(ip, username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, ipKey(ip))
	delete(l.entries, userKey(username))
}

// Prune drops IPs and accounts with no recent failures and no lockout.
func (l *loginLimiter) Prune() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(l.now())
}

func (l *loginLimiter) prune(now time.Time) {
	for key, a := range l.entries {
		a.failures = recentOnly(a.failures, now.Add(-l.window))
		if len(a.failures) == 0 && !a.lockedUntil.After(now) {
			delete(l.entries, key)
		}
	}
}

// recentOnly keeps the times after since. They are in order, oldest first.
func recentOnly(times []time.Time, since time.Time) []time.Time {
	for i, t := range times {
		if t.After(since) {
			return times[i:]
		}
	}
	return times[:0]
}

// callLimiter counts calls per key within a sliding window, for limits on
// things that succeed: the guest login is public, so successful guest logins
// and the weather API calls they allow are capped per client IP. Counts are
// kept in memory.
type callLimiter struct {
	mu      sync.Mutex
	window  time.Duration
	entries map[string][]time.Time
	now     func() time.Time
}

var (
	guestAPILimiter   *callLimiter // weather API calls, per guest IP and endpoint
	guestLoginLimiter *callLimiter // successful guest logins, per IP
)

func newCallLimiter(window time.Duration) *callLimiter {
	return &callLimiter{
		window:  window,
		entries: make(map[string][]time.Time),
		now:     time.Now,
	}
}

// Allow records a call for key if fewer than limit were made within the
// window, and returns 0. Otherwise it records nothing and returns how long
// until the next call may be made.
func (l *callLimiter) Allow(key string, limit int) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	calls, tracked := l.entries[key]
	if !tracked && len(l.entries) >= maxLimiterEntries {
		l.prune(now)
		if len(l.entries) >= maxLimiterEntries {
			// Too many keys to track: refuse rather than go unlimited
			return l.window
		}
	}

	calls = recentOnly(calls, now.Add(-l.window))
	if len(calls) >= limit {
		l.entries[key] = calls
		return calls[0].Add(l.window).Sub(now)
	}
	l.entries[key] = append(calls, now)
	return 0
}

// Prune drops keys with no calls within the window.
func (l *callLimiter) Prune() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(l.now())
}

func (l *callLimiter) prune(now time.Time) {
	for key, calls := range l.entries {
		if calls = recentOnly(calls, now.Add(-l.window)); len(calls) == 0 {
			delete(l.entries, key)
		} else {
			l.entries[key] = calls
		}
	}
}

// guestCallsPerLoad lists the weather endpoints the dashboard calls more than
// once per load (wind feeds both the speed and the direction chart).
var guestCallsPerLoad = map[string]int{"/api/wind": 2}

// guestAPILimit is how many calls a guest IP may make to a weather API
// endpoint per minute: the configured page loads per minute, times the
// calls the dashboard makes to it per load.
func guestAPILimit(path string) int {
	return config.Auth.GuestLoadsPerMinute * max(guestCallsPerLoad[path], 1)
}
