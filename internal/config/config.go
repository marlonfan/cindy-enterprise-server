package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr              string
	PublicBaseURL           string
	Region                  string
	DataDir                 string
	JWTIssuer               string
	JWTSecret               string
	AccessTokenTTL          time.Duration
	RefreshTokenTTL         time.Duration
	OIDCIssuerURL           string
	OIDCClientID            string
	OIDCClientSecret        string
	OIDCRedirectURL         string
	OIDCOrgID               string
	OIDCOrgName             string
	OIDCOrgDomain           string
	OIDCConnectionName      string
	DevLoginCode            string
	SMTPHost                string
	SMTPPort                int
	SMTPUsername            string
	SMTPPassword            string
	SMTPFromAddress         string
	SMTPFromName            string
	SMTPTLSMode             string
	SMTPServerName          string
	SMTPTimeout             time.Duration
	EmailCodeTTL            time.Duration
	EmailCodeResendInterval time.Duration
	EmailCodeMaxAttempts    int
	EmailCodeHourlyLimit    int
	ModelGatewayEndpoint    string
	ModelGatewayClientKey   string
	ModelGatewayUpstream    string
	ModelGatewayUpstreamKey string
	ModelCatalogFile        string
	ModelListFile           string
	MediaSigningSecret      string
	MediaURLTTL             time.Duration
	TrustedProxyHeaders     bool
}

func Load() (Config, error) {
	dataDir := env("DATA_DIR", "./data")
	absDataDir, err := filepath.Abs(dataDir)
	if err != nil {
		return Config{}, fmt.Errorf("resolve DATA_DIR: %w", err)
	}
	cfg := Config{
		ListenAddr:              env("LISTEN_ADDR", ":8080"),
		PublicBaseURL:           trimRightSlash(env("PUBLIC_BASE_URL", "http://localhost:8080")),
		Region:                  env("CINDY_REGION", "global"),
		DataDir:                 absDataDir,
		JWTIssuer:               env("JWT_ISSUER", "cindy-enterprise"),
		JWTSecret:               os.Getenv("JWT_SECRET"),
		AccessTokenTTL:          durationEnv("ACCESS_TOKEN_TTL", 15*time.Minute),
		RefreshTokenTTL:         durationEnv("REFRESH_TOKEN_TTL", 30*24*time.Hour),
		OIDCIssuerURL:           trimRightSlash(os.Getenv("OIDC_ISSUER_URL")),
		OIDCClientID:            os.Getenv("OIDC_CLIENT_ID"),
		OIDCClientSecret:        os.Getenv("OIDC_CLIENT_SECRET"),
		OIDCRedirectURL:         os.Getenv("OIDC_REDIRECT_URL"),
		OIDCOrgID:               env("OIDC_ORG_ID", "enterprise"),
		OIDCOrgName:             env("OIDC_ORG_NAME", "Enterprise"),
		OIDCOrgDomain:           strings.ToLower(strings.TrimSpace(os.Getenv("OIDC_ORG_DOMAIN"))),
		OIDCConnectionName:      env("OIDC_CONNECTION_NAME", "Enterprise SSO"),
		DevLoginCode:            os.Getenv("DEV_LOGIN_CODE"),
		SMTPHost:                strings.TrimSpace(os.Getenv("SMTP_HOST")),
		SMTPPort:                intEnv("SMTP_PORT", 587),
		SMTPUsername:            strings.TrimSpace(os.Getenv("SMTP_USERNAME")),
		SMTPPassword:            os.Getenv("SMTP_PASSWORD"),
		SMTPFromAddress:         strings.TrimSpace(os.Getenv("SMTP_FROM_ADDRESS")),
		SMTPFromName:            env("SMTP_FROM_NAME", "Cindy Enterprise"),
		SMTPTLSMode:             strings.ToLower(env("SMTP_TLS_MODE", "auto")),
		SMTPServerName:          strings.TrimSpace(os.Getenv("SMTP_SERVER_NAME")),
		SMTPTimeout:             durationEnv("SMTP_TIMEOUT", 15*time.Second),
		EmailCodeTTL:            durationEnv("EMAIL_CODE_TTL", 10*time.Minute),
		EmailCodeResendInterval: durationEnv("EMAIL_CODE_RESEND_INTERVAL", 42*time.Second),
		EmailCodeMaxAttempts:    intEnv("EMAIL_CODE_MAX_ATTEMPTS", 5),
		EmailCodeHourlyLimit:    intEnv("EMAIL_CODE_MAX_SENDS_PER_HOUR", 6),
		ModelGatewayEndpoint:    trimRightSlash(os.Getenv("MODEL_GATEWAY_ENDPOINT")),
		ModelGatewayClientKey:   os.Getenv("MODEL_GATEWAY_CLIENT_KEY"),
		ModelGatewayUpstream:    trimRightSlash(os.Getenv("MODEL_GATEWAY_UPSTREAM")),
		ModelGatewayUpstreamKey: os.Getenv("MODEL_GATEWAY_UPSTREAM_KEY"),
		ModelCatalogFile:        os.Getenv("MODEL_CATALOG_FILE"),
		ModelListFile:           os.Getenv("MODEL_LIST_FILE"),
		MediaSigningSecret:      os.Getenv("MEDIA_SIGNING_SECRET"),
		MediaURLTTL:             durationEnv("MEDIA_URL_TTL", 15*time.Minute),
		TrustedProxyHeaders:     boolEnv("TRUST_PROXY_HEADERS", false),
	}
	if cfg.JWTSecret == "" {
		return Config{}, errors.New("JWT_SECRET is required")
	}
	if len(cfg.JWTSecret) < 32 {
		return Config{}, errors.New("JWT_SECRET must be at least 32 characters")
	}
	if cfg.MediaSigningSecret == "" {
		cfg.MediaSigningSecret = cfg.JWTSecret
	}
	if cfg.Region != "cn" && cfg.Region != "global" {
		return Config{}, errors.New("CINDY_REGION must be cn or global")
	}
	if cfg.OIDCIssuerURL != "" {
		if cfg.OIDCClientID == "" || cfg.OIDCClientSecret == "" {
			return Config{}, errors.New("OIDC_CLIENT_ID and OIDC_CLIENT_SECRET are required when OIDC_ISSUER_URL is set")
		}
		if cfg.OIDCRedirectURL == "" {
			cfg.OIDCRedirectURL = cfg.PublicBaseURL + "/api/auth/oidc/callback"
		}
	}
	if cfg.SMTPHost == "" {
		if cfg.SMTPUsername != "" || cfg.SMTPPassword != "" || cfg.SMTPFromAddress != "" || cfg.SMTPServerName != "" {
			return Config{}, errors.New("SMTP_HOST is required when SMTP settings are configured")
		}
	} else {
		if cfg.SMTPFromAddress == "" {
			cfg.SMTPFromAddress = cfg.SMTPUsername
		}
		if cfg.SMTPFromAddress == "" {
			return Config{}, errors.New("SMTP_FROM_ADDRESS or SMTP_USERNAME is required when SMTP_HOST is set")
		}
		if (cfg.SMTPUsername == "") != (cfg.SMTPPassword == "") {
			return Config{}, errors.New("SMTP_USERNAME and SMTP_PASSWORD must be configured together")
		}
		if cfg.SMTPPort < 1 || cfg.SMTPPort > 65535 {
			return Config{}, errors.New("SMTP_PORT must be between 1 and 65535")
		}
		if cfg.SMTPTLSMode != "auto" && cfg.SMTPTLSMode != "tls" && cfg.SMTPTLSMode != "starttls" {
			return Config{}, errors.New("SMTP_TLS_MODE must be auto, tls, or starttls")
		}
		if cfg.SMTPTimeout <= 0 {
			return Config{}, errors.New("SMTP_TIMEOUT must be positive")
		}
	}
	if cfg.EmailCodeTTL <= 0 || cfg.EmailCodeTTL > 24*time.Hour {
		return Config{}, errors.New("EMAIL_CODE_TTL must be positive and no more than 24h")
	}
	if cfg.EmailCodeResendInterval <= 0 {
		return Config{}, errors.New("EMAIL_CODE_RESEND_INTERVAL must be positive")
	}
	if cfg.EmailCodeMaxAttempts < 1 || cfg.EmailCodeMaxAttempts > 20 {
		return Config{}, errors.New("EMAIL_CODE_MAX_ATTEMPTS must be between 1 and 20")
	}
	if cfg.EmailCodeHourlyLimit < 1 || cfg.EmailCodeHourlyLimit > 100 {
		return Config{}, errors.New("EMAIL_CODE_MAX_SENDS_PER_HOUR must be between 1 and 100")
	}
	if cfg.ModelGatewayUpstream != "" {
		if cfg.ModelGatewayClientKey == "" {
			return Config{}, errors.New("MODEL_GATEWAY_CLIENT_KEY is required when MODEL_GATEWAY_UPSTREAM is set")
		}
		cfg.ModelGatewayEndpoint = cfg.PublicBaseURL + "/api/gateway"
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return Config{}, fmt.Errorf("create DATA_DIR: %w", err)
	}
	return cfg, nil
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func durationEnv(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func boolEnv(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func intEnv(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func trimRightSlash(value string) string {
	return strings.TrimRight(strings.TrimSpace(value), "/")
}
