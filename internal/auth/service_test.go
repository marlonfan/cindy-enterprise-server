package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marlonfan/cindy-enterprise-server/internal/config"
	"github.com/marlonfan/cindy-enterprise-server/internal/mail"
	"github.com/marlonfan/cindy-enterprise-server/internal/store"
)

var standaloneCodePattern = regexp.MustCompile(`(?m)^([0-9]{6})$`)

func TestDevLoginRefreshAndMe(t *testing.T) {
	t.Parallel()
	cfg := config.Config{
		Region: "global", JWTIssuer: "test", JWTSecret: "01234567890123456789012345678901",
		AccessTokenTTL: time.Hour, RefreshTokenTTL: 24 * time.Hour,
		OIDCOrgID: "acme", OIDCOrgName: "Acme", OIDCOrgDomain: "acme.test", DevLoginCode: "123456",
	}
	dataStore, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(context.Background(), cfg, dataStore, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	service.Register(mux)
	server := httptest.NewServer(mux)
	defer server.Close()

	login := postJSON(t, server.URL+"/api/auth/email/verify-code", map[string]any{
		"email": "user@acme.test", "code": "123456", "deviceId": "desktop-1", "clientType": "desktop", "locale": "zh-CN",
	}, "")
	if login.StatusCode != http.StatusOK {
		t.Fatalf("login status=%d body=%s", login.StatusCode, readBody(login))
	}
	var pair struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
	}
	decodeBody(t, login, &pair)
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatal("token pair is empty")
	}
	claims, err := service.Signer().Verify(pair.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if claims.OrgSlug != "acme" || claims.DeviceID != "desktop-1" {
		t.Fatalf("unexpected claims: %+v", claims)
	}

	request, _ := http.NewRequest(http.MethodGet, server.URL+"/api/me", nil)
	request.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("me status=%d body=%s", response.StatusCode, readBody(response))
	}
	var me struct {
		Membership Membership `json:"membership"`
	}
	decodeBody(t, response, &me)
	if me.Membership.DisplayName != "user@acme.test" || me.Membership.Kind != "org" {
		t.Fatalf("unexpected membership: %+v", me.Membership)
	}

	refresh := postJSON(t, server.URL+"/api/auth/refresh", map[string]string{"refreshToken": pair.RefreshToken, "deviceId": "desktop-1"}, "")
	if refresh.StatusCode != http.StatusOK {
		t.Fatalf("refresh status=%d body=%s", refresh.StatusCode, readBody(refresh))
	}
	var rotated struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
	}
	decodeBody(t, refresh, &rotated)
	replay := postJSON(t, server.URL+"/api/auth/refresh", map[string]string{"refreshToken": pair.RefreshToken, "deviceId": "desktop-1"}, "")
	if replay.StatusCode != http.StatusUnauthorized {
		t.Fatalf("refresh replay status=%d", replay.StatusCode)
	}
	_ = replay.Body.Close()
	logout := postJSON(t, server.URL+"/api/auth/logout", map[string]any{}, rotated.AccessToken)
	if logout.StatusCode != http.StatusOK {
		t.Fatalf("logout status=%d", logout.StatusCode)
	}
	_ = logout.Body.Close()
	afterLogout := postJSON(t, server.URL+"/api/auth/refresh", map[string]string{"refreshToken": rotated.RefreshToken, "deviceId": "desktop-1"}, "")
	if afterLogout.StatusCode != http.StatusUnauthorized {
		t.Fatalf("refresh after logout status=%d", afterLogout.StatusCode)
	}
	_ = afterLogout.Body.Close()
}

func TestEmailCodeLifecycleAndRateLimit(t *testing.T) {
	t.Parallel()
	sender := &captureVerificationSender{}
	service, server := newEmailAuthServer(t, emailTestConfig(), sender)
	now := time.Date(2026, time.August, 2, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }

	providers, err := http.Get(server.URL + "/api/auth/providers")
	if err != nil {
		t.Fatal(err)
	}
	var providerBody struct {
		Email bool `json:"email"`
	}
	decodeBody(t, providers, &providerBody)
	if !providerBody.Email {
		t.Fatal("email provider should be enabled when SMTP sender is configured")
	}

	request := postJSON(t, server.URL+"/api/auth/email/request-code", map[string]string{
		"email": "User@Acme.Test", "locale": "zh-CN",
	}, "")
	if request.StatusCode != http.StatusOK {
		t.Fatalf("request code status=%d body=%s", request.StatusCode, readBody(request))
	}
	_ = request.Body.Close()
	code := sender.lastCode(t)
	if sender.lastRecipient() != "user@acme.test" {
		t.Fatalf("unexpected normalized recipient: %q", sender.lastRecipient())
	}

	limited := postJSON(t, server.URL+"/api/auth/email/request-code", map[string]string{
		"email": "user@acme.test", "locale": "zh-CN",
	}, "")
	if limited.StatusCode != http.StatusTooManyRequests || limited.Header.Get("Retry-After") != "42" {
		t.Fatalf("rate limit status=%d retry=%q body=%s", limited.StatusCode, limited.Header.Get("Retry-After"), readBody(limited))
	}
	_ = limited.Body.Close()

	login := postJSON(t, server.URL+"/api/auth/email/verify-code", map[string]string{
		"email": "USER@ACME.TEST", "code": code, "deviceId": "desktop-1", "clientType": "desktop", "locale": "zh-CN",
	}, "")
	if login.StatusCode != http.StatusOK {
		t.Fatalf("login status=%d body=%s", login.StatusCode, readBody(login))
	}
	_ = login.Body.Close()

	replay := postJSON(t, server.URL+"/api/auth/email/verify-code", map[string]string{
		"email": "user@acme.test", "code": code, "deviceId": "desktop-1", "clientType": "desktop", "locale": "zh-CN",
	}, "")
	if replay.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed code status=%d body=%s", replay.StatusCode, readBody(replay))
	}
	_ = replay.Body.Close()
}

func TestEmailCodeAttemptLimitAndExpiry(t *testing.T) {
	t.Parallel()
	cfg := emailTestConfig()
	cfg.EmailCodeTTL = 2 * time.Minute
	cfg.EmailCodeMaxAttempts = 2
	sender := &captureVerificationSender{}
	service, server := newEmailAuthServer(t, cfg, sender)
	now := time.Date(2026, time.August, 2, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }

	requestEmailCode(t, server.URL, "user@acme.test")
	code := sender.lastCode(t)
	wrongCode := differentCode(code)
	for range 2 {
		response := verifyEmailCode(t, server.URL, "user@acme.test", wrongCode)
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("wrong code status=%d body=%s", response.StatusCode, readBody(response))
		}
		_ = response.Body.Close()
	}
	exhausted := verifyEmailCode(t, server.URL, "user@acme.test", code)
	if exhausted.StatusCode != http.StatusUnauthorized {
		t.Fatalf("exhausted code status=%d body=%s", exhausted.StatusCode, readBody(exhausted))
	}
	_ = exhausted.Body.Close()

	now = now.Add(43 * time.Second)
	requestEmailCode(t, server.URL, "user@acme.test")
	expiringCode := sender.lastCode(t)
	now = now.Add(2 * time.Minute)
	expired := verifyEmailCode(t, server.URL, "user@acme.test", expiringCode)
	if expired.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired code status=%d body=%s", expired.StatusCode, readBody(expired))
	}
	_ = expired.Body.Close()
}

func TestEmailDeliveryFailureDoesNotCreateChallenge(t *testing.T) {
	t.Parallel()
	sender := &captureVerificationSender{err: errors.New("SMTP unavailable")}
	service, server := newEmailAuthServer(t, emailTestConfig(), sender)
	service.now = func() time.Time { return time.Date(2026, time.August, 2, 12, 0, 0, 0, time.UTC) }

	response := postJSON(t, server.URL+"/api/auth/email/request-code", map[string]string{
		"email": "user@acme.test", "locale": "zh-CN",
	}, "")
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("delivery failure status=%d body=%s", response.StatusCode, readBody(response))
	}
	_ = response.Body.Close()
	if len(service.emailChallenges) != 0 {
		t.Fatal("failed delivery must not create a verification challenge")
	}
}

type captureVerificationSender struct {
	mu         sync.Mutex
	recipients []string
	messages   []mail.Email
	err        error
}

func (s *captureVerificationSender) SendVerificationCode(_ context.Context, recipient string, message mail.Email) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recipients = append(s.recipients, recipient)
	s.messages = append(s.messages, message)
	return s.err
}

func (s *captureVerificationSender) lastCode(t *testing.T) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.messages) == 0 {
		t.Fatal("no verification email was captured")
	}
	match := standaloneCodePattern.FindStringSubmatch(s.messages[len(s.messages)-1].PlainText)
	if len(match) != 2 {
		t.Fatalf("verification code missing from plain text: %q", s.messages[len(s.messages)-1].PlainText)
	}
	return match[1]
}

func (s *captureVerificationSender) lastRecipient() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.recipients) == 0 {
		return ""
	}
	return s.recipients[len(s.recipients)-1]
}

func emailTestConfig() config.Config {
	return config.Config{
		Region: "global", JWTIssuer: "test", JWTSecret: "01234567890123456789012345678901",
		AccessTokenTTL: time.Hour, RefreshTokenTTL: 24 * time.Hour,
		OIDCOrgID: "acme", OIDCOrgName: "Acme", OIDCOrgDomain: "acme.test", DevLoginCode: "123456",
		SMTPFromAddress: "support@acme.test", SMTPFromName: "Cindy Enterprise",
		EmailCodeTTL: 10 * time.Minute, EmailCodeResendInterval: 42 * time.Second,
		EmailCodeMaxAttempts: 5, EmailCodeHourlyLimit: 6,
	}
}

func newEmailAuthServer(t *testing.T, cfg config.Config, sender mail.VerificationSender) (*Service, *httptest.Server) {
	t.Helper()
	dataStore, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(context.Background(), cfg, dataStore, slog.New(slog.NewTextHandler(io.Discard, nil)), sender)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	service.Register(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return service, server
}

func requestEmailCode(t *testing.T, serverURL, email string) {
	t.Helper()
	response := postJSON(t, serverURL+"/api/auth/email/request-code", map[string]string{"email": email, "locale": "zh-CN"}, "")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("request code status=%d body=%s", response.StatusCode, readBody(response))
	}
	_ = response.Body.Close()
}

func verifyEmailCode(t *testing.T, serverURL, email, code string) *http.Response {
	t.Helper()
	return postJSON(t, serverURL+"/api/auth/email/verify-code", map[string]string{
		"email": email, "code": code, "deviceId": "desktop-1", "clientType": "desktop", "locale": "zh-CN",
	}, "")
}

func differentCode(code string) string {
	replacement := "0"
	if strings.HasPrefix(code, replacement) {
		replacement = "1"
	}
	return replacement + code[1:]
}

func postJSON(t *testing.T, url string, body any, token string) *http.Response {
	t.Helper()
	encoded, _ := json.Marshal(body)
	request, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func decodeBody(t *testing.T, response *http.Response, dst any) {
	t.Helper()
	defer response.Body.Close()
	if err := json.NewDecoder(response.Body).Decode(dst); err != nil {
		t.Fatal(err)
	}
}

func readBody(response *http.Response) string {
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	return string(data)
}
