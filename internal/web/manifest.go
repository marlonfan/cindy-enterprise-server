package web

import (
	"net/http"

	"github.com/marlonfan/cindy-enterprise-server/internal/config"
)

func RegisterManifest(mux *http.ServeMux, cfg config.Config) {
	mux.HandleFunc("GET /endpoint.json", func(w http.ResponseWriter, _ *http.Request) {
		JSON(w, http.StatusOK, map[string]any{
			"schemaVersion":          1,
			"authApiBaseUrl":         cfg.PublicBaseURL,
			"deviceLinkApiBaseUrl":   cfg.PublicBaseURL,
			"oauthBrokerApiBaseUrl":  "",
			"ossApiBaseUrl":          cfg.PublicBaseURL,
			"heartbeatUrl":           cfg.PublicBaseURL,
			"telegramHookWsUrl":      "",
			"xHookWsUrl":             "",
			"slackHookWsUrl":         "",
			"websiteUrl":             cfg.PublicBaseURL,
			"modelAccessApiBaseUrl":  cfg.PublicBaseURL,
			"voiceApiBaseUrl":        "",
			"githubApiBaseUrl":       "",
			"skillhubApiBaseUrl":     "",
			"pluginApiBaseUrl":       "",
			"cdnBaseUrl":             "",
			"mobileUpdateBaseUrl":    "",
			"authDesktopCallbackUrl": cfg.PublicBaseURL + "/api/auth/desktop/callback",
			"review":                 "",
		})
	})
	// Compatibility with clients that append an extra endpoint.json to the bootstrap base.
	mux.HandleFunc("GET /endpoint.json/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/endpoint.json", http.StatusPermanentRedirect)
	})
}
