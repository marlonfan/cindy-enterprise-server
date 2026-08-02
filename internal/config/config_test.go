package config

import (
	"testing"
	"time"
)

func TestLoadSMTPDefaults(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("DATA_DIR", t.TempDir())
	t.Setenv("JWT_SECRET", "01234567890123456789012345678901")
	t.Setenv("SMTP_HOST", "mail.example.test")
	t.Setenv("SMTP_USERNAME", "sender@example.test")
	t.Setenv("SMTP_PASSWORD", "secret")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SMTPPort != 587 || cfg.SMTPTLSMode != "auto" || cfg.SMTPFromAddress != "sender@example.test" {
		t.Fatalf("unexpected SMTP defaults: %+v", cfg)
	}
	if cfg.EmailCodeTTL != 10*time.Minute || cfg.EmailCodeResendInterval != 42*time.Second {
		t.Fatalf("unexpected email code durations: ttl=%s resend=%s", cfg.EmailCodeTTL, cfg.EmailCodeResendInterval)
	}
	if cfg.EmailCodeMaxAttempts != 5 || cfg.EmailCodeHourlyLimit != 6 {
		t.Fatalf("unexpected email code limits: attempts=%d sends=%d", cfg.EmailCodeMaxAttempts, cfg.EmailCodeHourlyLimit)
	}
}

func TestLoadRejectsPartialSMTPAuth(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("DATA_DIR", t.TempDir())
	t.Setenv("JWT_SECRET", "01234567890123456789012345678901")
	t.Setenv("SMTP_HOST", "mail.example.test")
	t.Setenv("SMTP_USERNAME", "sender@example.test")

	if _, err := Load(); err == nil {
		t.Fatal("expected partial SMTP authentication to fail")
	}
}

func clearConfigEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"DATA_DIR", "JWT_SECRET", "SMTP_HOST", "SMTP_PORT", "SMTP_USERNAME", "SMTP_PASSWORD",
		"SMTP_FROM_ADDRESS", "SMTP_FROM_NAME", "SMTP_TLS_MODE", "SMTP_SERVER_NAME", "SMTP_TIMEOUT",
		"EMAIL_CODE_TTL", "EMAIL_CODE_RESEND_INTERVAL", "EMAIL_CODE_MAX_ATTEMPTS", "EMAIL_CODE_MAX_SENDS_PER_HOUR",
	} {
		t.Setenv(key, "")
	}
}
