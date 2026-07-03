// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the PolyForm Shield License 1.0.0.
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://polyformproject.org/licenses/shield/1.0.0/
//
//     or in the LICENSE file in this repository.
//
// Required Notice: Copyright Swissmakers GmbH (https://swissmakers.ch)

package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/internal/auth"
	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/storage"
	"github.com/swissmakers/fail2ban-ui/pkg/web"
)

// =========================================================================
//  Entrypoint
// =========================================================================

func main() {
	settings := config.GetSettings()

	// Initialize base path
	web.SetBasePathFromEnv()
	auth.SetSessionCookiePath(web.CookiePath())

	// Initialize storage
	if err := storage.Init(""); err != nil {
		log.Fatalf("Failed to initialise storage: %v", err)
	}
	defer func() {
		if err := storage.Close(); err != nil {
			log.Printf("warning: failed to close storage: %v", err)
		}
	}()

	// Initialize Fail2ban connectors (local filesystem bootstrap and active connectors)
	if err := config.ReloadFail2banManager(); err != nil {
		log.Fatalf("failed to initialise fail2ban connectors: %v", err)
	}

	// Initialize OIDC or local authentication
	oidcConfig, err := config.GetOIDCConfigFromEnv()
	if err != nil {
		log.Fatalf("failed to load OIDC configuration: %v", err)
	}
	if oidcConfig != nil && oidcConfig.Enabled {
		if err := auth.InitializeSessionSecret(oidcConfig.SessionSecret); err != nil {
			log.Fatalf("failed to initialize session secret: %v", err)
		}
		if _, err := auth.InitializeOIDC(oidcConfig); err != nil {
			log.Fatalf("failed to initialize OIDC: %v", err)
		}
		log.Println("OIDC authentication enabled")
	} else {
		if err := auth.InitializeLocalAuth(); err != nil {
			log.Fatalf("failed to initialize local authentication: %v", err)
		}
		if auth.IsLocalAuthEnabled() {
			log.Printf("Local authentication enabled for user: %s", auth.GetLocalUsername())
		}
	}

	// Set Gin mode
	if settings.Debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// Initialize router
	// Use gin.New() instead of gin.Default() to avoid logging sensitive request paths.
	router := gin.New()
	router.Use(gin.Recovery()) // Keep panic recovery

	// [FIX C1] Disable X-Forwarded-For trust to prevent rate-limiter bypass via IP spoofing.
	// Only set trusted proxies explicitly if running behind a known reverse proxy.
	if err := router.SetTrustedProxies(nil); err != nil {
		log.Fatalf("failed to set trusted proxies: %v", err)
	}

	serverPort := strconv.Itoa(int(settings.Port))
	bindAddress, _ := config.GetBindAddressFromEnv()
	serverAddr := net.JoinHostPort(bindAddress, serverPort)

	if err := web.MountEmbeddedAssets(router); err != nil {
		log.Fatalf("failed to mount embedded web assets: %v", err)
	}

	// Initialize WebSocket hub and console log capture
	wsHub := web.NewHub()
	go wsHub.Run()
	web.SetupConsoleLogWriter(wsHub)
	web.UpdateConsoleLogEnabled()
	config.SetUpdateConsoleLogStateFunc(func(enabled bool) {
		web.SetConsoleLogEnabled(enabled)
	})

	// Register routes
	web.RegisterRoutes(router, wsHub)
	isLOTRMode := config.IsLOTRModeActive(settings.AlertCountries)
	printWelcomeBanner(bindAddress, serverPort, isLOTRMode)
	if isLOTRMode {
		log.Println("--- Middle-earth Security Realm activated ---")
		log.Println("🎭 LOTR Mode: The guardians of Middle-earth stand ready!")
	} else {
		log.Println("--- Fail2Ban-UI started in", gin.Mode(), "mode ---")
	}
	if bp := web.BasePath(); bp != "" {
		log.Printf("HTTP base path: %s (from BASE_PATH)\n", bp)
	}
	log.Printf("Server listening on %s:%s.\n", bindAddress, serverPort)

	// [FIX C3] Set server timeouts to defend against Slowloris and resource exhaustion.
	server := &http.Server{
		Addr:         serverAddr,
		Handler:      web.StripBasePathHandler(router),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Could not start server: %v\n", err)
	}
}

// Print welcome banner.
func printWelcomeBanner(bindAddress, appPort string, isLOTRMode bool) {
	greeting := getGreeting()

	if isLOTRMode {
		const lotrBanner = `
      .--.
     |o_o |     %s
     |:_/ |
    //   \ \
   (|     | )
  /'\_   _/'\
  \___)=(___/

Middle-earth Security Realm - LOTR Mode Activated
══════════════════════════════════════════════════
⚔️  The guardians of Middle-earth stand ready!  ⚔️
Developers:   https://swissmakers.ch
Mode:         %s
Listening on: http://%s:%s
══════════════════════════════════════════════════

`
		fmt.Printf(lotrBanner, greeting, gin.Mode(), bindAddress, appPort)
	} else {
		const tuxBanner = `
      .--.
     |o_o |     %s
     |:_/ |
    //   \ \
   (|     | )
  /'\_   _/'\
  \___)=(___/

Fail2Ban UI - A Swissmade Management Interface
----------------------------------------------
Developers:   https://swissmakers.ch
Mode:         %s
Listening on: http://%s:%s
----------------------------------------------

`
		fmt.Printf(tuxBanner, greeting, gin.Mode(), bindAddress, appPort)
	}
}

func getGreeting() string {
	hour := time.Now().Hour()
	switch {
	case hour < 12:
		return "Good morning!"
	case hour < 18:
		return "Good afternoon!"
	default:
		return "Good evening!"
	}
}
