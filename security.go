package main

import (
	"log"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// minPasswordLength applies to new passwords; existing ones keep working.
const minPasswordLength = 12

// dummyPasswordHash is a bcrypt hash (same cost as real ones) of a random
// password, compared against when a username doesn't exist.
const dummyPasswordHash = "$2a$10$mLUUV7de2qBtTdlzWCw5CO0.AUDMHOuohR9LHetMSGhk1lo8Oz1tO"

// localNets is auth.local_networks, parsed; empty means private addresses.
var localNets []*net.IPNet

// isLocalIP reports whether ip is on the home network (or this machine).
func isLocalIP(ip string) bool {
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	if addr.IsLoopback() {
		return true
	}
	if len(localNets) == 0 {
		return addr.IsPrivate()
	}
	for _, n := range localNets {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}

// allowedFrom reports whether username may sign in or stay signed in from ip,
// given auth.local_only_users.
func allowedFrom(username, ip string) bool {
	return !slices.Contains(config.Auth.LocalOnlyUsers, username) || isLocalIP(ip)
}

// secureHeaders adds browser protections to every response, and refuses
// form posts and API calls sent from another site (cross-site request
// forgery), on top of the session cookie's SameSite=Lax.
func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "SAMEORIGIN")
		h.Set("Referrer-Policy", "same-origin")
		if !sameOrigin(r) {
			log.Printf("Refused cross-site %s %s from origin %q (%s)", r.Method, r.URL.Path, r.Header.Get("Origin"), clientIP(r))
			http.Error(w, "Forbidden: request came from another site", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sameOrigin reports whether a request that can change something was sent
// by a page on this site. Browsers send Origin with every POST; requests
// without one don't come from another site's page.
func sameOrigin(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	// Compare host names only: nginx passes Host without the port
	return strings.EqualFold(u.Hostname(), hostOnly(r.Host))
}

func hostOnly(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	return strings.Trim(hostport, "[]")
}
