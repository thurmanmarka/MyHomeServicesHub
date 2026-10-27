package main

import (
	"testing"
	"time"
)

func testLimiter() (*loginLimiter, *time.Time) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	l := newLoginLimiter(3, 5, 15*time.Minute, 15*time.Minute)
	l.now = func() time.Time { return now }
	return l, &now
}

func TestLimiterLocksIPAfterLimit(t *testing.T) {
	l, now := testLimiter()
	for i := 0; i < 2; i++ {
		if got := l.Failure("1.2.3.4", "admin", true); len(got) != 0 {
			t.Fatalf("failure %d locked %v too early", i+1, got)
		}
	}
	got := l.Failure("1.2.3.4", "admin", true)
	if len(got) != 1 || got[0] != (Lockout{"IP address", "1.2.3.4"}) {
		t.Fatalf("third failure locked %v, want the IP", got)
	}
	if l.Blocked("1.2.3.4", "someone-else") == 0 {
		t.Error("IP should be blocked for every username")
	}
	if l.Blocked("5.6.7.8", "admin") != 0 {
		t.Error("account should not be locked yet")
	}

	*now = now.Add(15*time.Minute + time.Second)
	if l.Blocked("1.2.3.4", "admin") != 0 {
		t.Error("lockout should end")
	}
}

func TestLimiterLocksAccountAcrossIPs(t *testing.T) {
	l, _ := testLimiter()
	ips := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"}
	for _, ip := range ips {
		l.Failure(ip, "admin", true)
	}
	got := l.Failure("5.5.5.5", "admin", true)
	if len(got) != 1 || got[0] != (Lockout{"account", "admin"}) {
		t.Fatalf("fifth failure locked %v, want the account", got)
	}
	if l.Blocked("9.9.9.9", "admin") == 0 {
		t.Error("account should be blocked from any IP")
	}
	if l.Blocked("9.9.9.9", "guest") != 0 {
		t.Error("other accounts should not be blocked")
	}
}

func TestLimiterIgnoresUnknownAccounts(t *testing.T) {
	l, _ := testLimiter()
	for i := 0; i < 10; i++ {
		l.Failure(string(rune('a'+i))+".example", "nobody", false)
	}
	if _, ok := l.entries[userKey("nobody")]; ok {
		t.Error("unknown usernames should not be tracked")
	}
}

func TestLimiterFailuresOutsideWindowDontCount(t *testing.T) {
	l, now := testLimiter()
	l.Failure("1.2.3.4", "admin", true)
	l.Failure("1.2.3.4", "admin", true)
	*now = now.Add(16 * time.Minute)
	if got := l.Failure("1.2.3.4", "admin", true); len(got) != 0 {
		t.Fatalf("old failures were counted: locked %v", got)
	}
}

func TestLimiterSuccessClears(t *testing.T) {
	l, _ := testLimiter()
	l.Failure("1.2.3.4", "admin", true)
	l.Failure("1.2.3.4", "admin", true)
	l.Success("1.2.3.4", "admin")
	if got := l.Failure("1.2.3.4", "admin", true); len(got) != 0 {
		t.Fatalf("success didn't clear failures: locked %v", got)
	}
}

func TestLimiterPrune(t *testing.T) {
	l, now := testLimiter()
	l.Failure("1.2.3.4", "admin", true)
	for i := 0; i < 3; i++ {
		l.Failure("6.6.6.6", "guest", false)
	}
	*now = now.Add(16 * time.Minute)
	l.Prune()
	if len(l.entries) != 0 {
		t.Errorf("stale entries left after prune: %d", len(l.entries))
	}
}

func testCallLimiter(window time.Duration) (*callLimiter, *time.Time) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	l := newCallLimiter(window)
	l.now = func() time.Time { return now }
	return l, &now
}

func TestCallLimiterCapsPerKey(t *testing.T) {
	l, now := testCallLimiter(time.Minute)
	for i := 0; i < 15; i++ {
		if wait := l.Allow("1.2.3.4 /api/barometer", 15); wait != 0 {
			t.Fatalf("call %d refused too early", i+1)
		}
	}
	if wait := l.Allow("1.2.3.4 /api/barometer", 15); wait != time.Minute {
		t.Errorf("16th call within a minute: wait %s, want 1m", wait)
	}
	if l.Allow("1.2.3.4 /api/rain", 15) != 0 {
		t.Error("other keys have their own count")
	}

	*now = now.Add(time.Minute + time.Second)
	if l.Allow("1.2.3.4 /api/barometer", 15) != 0 {
		t.Error("calls older than the window should not count")
	}
}

func TestCallLimiterRefusedCallsDontCount(t *testing.T) {
	l, now := testCallLimiter(time.Hour)
	l.Allow("1.2.3.4", 1)
	for i := 0; i < 5; i++ {
		l.Allow("1.2.3.4", 1)
	}
	*now = now.Add(time.Hour + time.Second)
	if l.Allow("1.2.3.4", 1) != 0 {
		t.Error("refused calls kept the key blocked past the window")
	}
}

func TestCallLimiterPrune(t *testing.T) {
	l, now := testCallLimiter(time.Minute)
	l.Allow("1.2.3.4 /api/rain", 15)
	*now = now.Add(2 * time.Minute)
	l.Prune()
	if len(l.entries) != 0 {
		t.Errorf("stale entries kept: %v", l.entries)
	}
}

func TestGuestAPILimitCountsRepeatedEndpoints(t *testing.T) {
	config.Auth.GuestLoadsPerMinute = 15
	if got := guestAPILimit("/api/wind"); got != 30 {
		t.Errorf("wind limit %d, want 30", got)
	}
	if got := guestAPILimit("/api/rain"); got != 15 {
		t.Errorf("rain limit %d, want 15", got)
	}
}
