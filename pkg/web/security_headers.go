// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU General Public License, Version 3 (GPL-3.0)

package web

import (
	"strings"

	"github.com/gin-gonic/gin"
)

// [FIX C2] SecurityHeadersMiddleware adds essential HTTP security headers to every response.
// These headers defend against XSS, clickjacking, MIME sniffing, and information leakage.
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Prevent the page from being embedded in iframes (clickjacking defense)
		c.Header("X-Frame-Options", "DENY")

		// Prevent MIME type sniffing
		c.Header("X-Content-Type-Options", "nosniff")

		// Strict CSP: this is an admin SPA — no external resources needed
		c.Header("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline'; "+ // tailwind/inline scripts require unsafe-inline
				"style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; "+
				"font-src 'self'; "+
				"connect-src 'self' wss: ws:; "+ // WebSocket
				"frame-ancestors 'none'; "+
				"form-action 'self'",
		)

		// Prevent Referer header leaking session tokens or paths to third parties
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		// Disable browser features not needed by this dashboard
		c.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")

		// Prevent caching of authenticated pages by browsers and intermediary proxies
		if strings.HasPrefix(c.Request.URL.Path, "/api/") || c.Request.URL.Path == "/" {
			c.Header("Cache-Control", "no-store, no-cache, must-revalidate, private")
			c.Header("Pragma", "no-cache")
		}

		// Enforce HTTPS if the request arrives over a secure channel
		if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		c.Next()
	}
}
