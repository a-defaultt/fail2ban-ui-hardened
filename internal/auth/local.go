// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU General Public License, Version 3 (GPL-3.0)
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.gnu.org/licenses/gpl-3.0.en.html
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type LocalAuthConfig struct {
	Enabled       bool
	Username      string
	Password      string // Plain text password or bcrypt hash
	SessionMaxAge int
}

type AttemptInfo struct {
	Attempts     int
	BlockedUntil time.Time
	LastSeen     time.Time
}

var (
	localConfig  LocalAuthConfig
	loginLimiter = struct {
		sync.RWMutex
		attempts map[string]*AttemptInfo
	}{
		attempts: make(map[string]*AttemptInfo),
	}
)

func InitializeLocalAuth() error {
	// If NO_AUTH is enabled, we completely disable authentication.
	if os.Getenv("NO_AUTH") == "true" || os.Getenv("NO_AUTH") == "1" {
		log.Println("WARNING: NO_AUTH is set — authentication is DISABLED. Never use in production.")
		localConfig.Enabled = false
		return nil
	}

	// If OIDC is enabled, disable local auth
	if oidcEnabled := os.Getenv("OIDC_ENABLED"); oidcEnabled == "true" || oidcEnabled == "1" {
		localConfig.Enabled = false
		return nil
	}

	localConfig.Enabled = true
	username := os.Getenv("SECURITY_USER")
	if username == "" {
		username = os.Getenv("ADMIN_USER") // fallback
	}
	if username == "" {
		username = "admin"
	}
	localConfig.Username = username

	// Check SECURITY_PASSWORD or SECURITY_PASSWORD_FILE
	password := os.Getenv("SECURITY_PASSWORD")
	if password == "" {
		password = os.Getenv("ADMIN_PASSWORD") // fallback
	}
	if password == "" {
		pwdFile := os.Getenv("SECURITY_PASSWORD_FILE")
		if pwdFile != "" {
			// [FIX M2] Use os.ReadFile instead of deprecated ioutil.ReadFile
			data, err := os.ReadFile(pwdFile)
			if err == nil {
				password = strings.TrimSpace(string(data))
			} else {
				log.Printf("Warning: Failed to read security password file %s: %v", pwdFile, err)
			}
		}
	}

	// Generate a secure random password on startup if none is set
	if password == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return fmt.Errorf("failed to generate random password: %w", err)
		}
		password = base64.RawURLEncoding.EncodeToString(b)
		// [FIX M3] Avoid printing the password where possible; suggest env var.
		// We must log it once since there's no other channel to deliver it.
		log.Printf("\n\n========================================================\n"+
			"SECURITY WARNING: No admin password set.\n"+
			"Generated temporary credentials for local authentication:\n"+
			"Username: %s\n"+
			"Password: %s\n"+
			"Set SECURITY_PASSWORD to silence this warning.\n"+
			"========================================================\n\n", username, password)
	}

	localConfig.Password = password

	maxAge := 86400 // 24 hours
	if maxAgeEnv := os.Getenv("SECURITY_SESSION_MAX_AGE"); maxAgeEnv != "" {
		if val, err := time.ParseDuration(maxAgeEnv); err == nil {
			maxAge = int(val.Seconds())
		} else {
			var valInt int
			if _, err := fmt.Sscanf(maxAgeEnv, "%d", &valInt); err == nil {
				maxAge = valInt
			}
		}
	}
	localConfig.SessionMaxAge = maxAge

	// Setup session secret if not already initialized
	sessionSecret := os.Getenv("SECURITY_SESSION_SECRET")
	if sessionSecret == "" {
		sessionSecret = os.Getenv("OIDC_SESSION_SECRET")
	}
	if sessionSecret == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return fmt.Errorf("failed to generate session secret: %w", err)
		}
		sessionSecret = base64.URLEncoding.EncodeToString(b)
		log.Println("WARNING: No SECURITY_SESSION_SECRET set. Generated ephemeral secret — all sessions will be invalidated on restart.")
	}

	if err := InitializeSessionSecret(sessionSecret); err != nil {
		return fmt.Errorf("failed to initialize session secret: %w", err)
	}

	// [FIX H3] Start background goroutine to garbage-collect stale rate-limiter entries.
	go cleanupRateLimiter()

	return nil
}

// cleanupRateLimiter removes entries from the rate-limiter map that have been
// idle for longer than the block duration, preventing unbounded memory growth.
func cleanupRateLimiter() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-20 * time.Minute) // keep entries for 20 min after last activity
		loginLimiter.Lock()
		for ip, info := range loginLimiter.attempts {
			if info.LastSeen.Before(cutoff) {
				delete(loginLimiter.attempts, ip)
			}
		}
		loginLimiter.Unlock()
	}
}

func IsLocalAuthEnabled() bool {
	return localConfig.Enabled
}

func GetLocalUsername() string {
	return localConfig.Username
}

func GetLocalSessionMaxAge() int {
	return localConfig.SessionMaxAge
}

// CheckCredentials checks username and password, with rate limiting / brute-force protection.
// The clientIP must be the real remote address — caller must ensure X-Forwarded-For is NOT used.
func CheckCredentials(username, password, clientIP string) (bool, string, error) {
	if !localConfig.Enabled {
		return false, "Authentication is disabled", nil
	}

	// Check if IP is currently blocked
	loginLimiter.RLock()
	info := loginLimiter.attempts[clientIP]
	if info != nil && time.Now().Before(info.BlockedUntil) {
		loginLimiter.RUnlock()
		remaining := time.Until(info.BlockedUntil).Round(time.Second)
		return false, fmt.Sprintf("Too many failed login attempts. IP blocked. Try again in %v", remaining), nil
	}
	loginLimiter.RUnlock()

	// Read current attempt count before the delay (lock-free read is fine here; worst case
	// we use a slightly stale value, which only affects the delay duration, not correctness).
	loginLimiter.RLock()
	attempts := 0
	if info != nil {
		attempts = info.Attempts
	}
	loginLimiter.RUnlock()

	// Progressive delay to slow automated attacks: 1s, 2s, ... max 10s
	if attempts > 0 {
		delay := time.Duration(attempts) * time.Second
		if delay > 10*time.Second {
			delay = 10 * time.Second
		}
		time.Sleep(delay)
	}

	// [FIX H4] Perform credential comparison safely:
	// Normalize username to a fixed-length canonical form BEFORE constant-time compare
	// so strings.ToLower cannot be used as a timing oracle.
	// Both sides are padded/truncated to the same length with a fixed zero-value byte
	// so ConstantTimeCompare always operates on equal-length slices.
	canonicalize := func(s string) []byte {
		b := []byte(strings.ToLower(s))
		// Pad to a fixed width so lengths don't leak via ConstantTimeCompare
		const maxLen = 256
		padded := make([]byte, maxLen)
		copy(padded, b)
		return padded
	}
	userMatch := subtle.ConstantTimeCompare(canonicalize(username), canonicalize(localConfig.Username)) == 1

	var pwdMatch bool
	if strings.HasPrefix(localConfig.Password, "$2a$") ||
		strings.HasPrefix(localConfig.Password, "$2b$") ||
		strings.HasPrefix(localConfig.Password, "$2y$") {
		// BCrypt hash — bcrypt.CompareHashAndPassword is already timing-safe
		err := bcrypt.CompareHashAndPassword([]byte(localConfig.Password), []byte(password))
		pwdMatch = (err == nil)
	} else {
		// Plain text — use constant-time compare
		pwdMatch = subtle.ConstantTimeCompare([]byte(password), []byte(localConfig.Password)) == 1
	}

	if userMatch && pwdMatch {
		// [FIX L2] Log successful logins for audit trail
		log.Printf("AUTH: Successful login for user '%s' from IP %s", localConfig.Username, clientIP)

		loginLimiter.Lock()
		delete(loginLimiter.attempts, clientIP)
		loginLimiter.Unlock()
		return true, "", nil
	}

	// Failure: Increment rate limiter
	loginLimiter.Lock()
	if loginLimiter.attempts[clientIP] == nil {
		loginLimiter.attempts[clientIP] = &AttemptInfo{}
	}
	entry := loginLimiter.attempts[clientIP]
	entry.Attempts++
	entry.LastSeen = time.Now()
	if entry.Attempts >= 5 {
		entry.BlockedUntil = time.Now().Add(15 * time.Minute)
		log.Printf("SECURITY WARNING: IP %s blocked for 15 minutes after %d failed login attempts.", clientIP, entry.Attempts)
	}
	loginLimiter.Unlock()

	// Generic error — do not differentiate between wrong user vs wrong password
	log.Printf("SECURITY WARNING: Failed login attempt for user '%s' from IP %s", username, clientIP)
	return false, "Invalid username or password", nil
}
