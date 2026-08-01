package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/marlonfan/cindy-enterprise-server/internal/config"
	"github.com/marlonfan/cindy-enterprise-server/internal/store"
)

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
	service, err := New(context.Background(), cfg, dataStore, slog.New(slog.NewTextHandler(io.Discard, nil)))
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
