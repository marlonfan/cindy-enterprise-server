package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/marlonfan/cindy-enterprise-server/internal/config"
	"github.com/marlonfan/cindy-enterprise-server/internal/store"
	"github.com/marlonfan/cindy-enterprise-server/internal/web"
)

type contextKey struct{}

type Membership struct {
	ID          string  `json:"id"`
	PassportID  string  `json:"passportId,omitempty"`
	Kind        string  `json:"kind"`
	Role        string  `json:"role"`
	DisplayName string  `json:"displayName"`
	AvatarURL   *string `json:"avatarUrl"`
	Email       *string `json:"email"`
	OrgID       *string `json:"orgId"`
	OrgName     *string `json:"orgName"`
	OrgLogoURL  *string `json:"orgLogoUrl"`
}

type authRequest struct {
	RedirectURI   string
	CodeChallenge string
	ClientState   string
	DeviceID      string
	ExpiresAt     time.Time
}

type authorizationCode struct {
	UserID        string
	DeviceID      string
	CodeChallenge string
	ExpiresAt     time.Time
}

type hostedResult struct {
	Status    string
	Code      string
	Error     string
	ExpiresAt time.Time
}

type Service struct {
	cfg         config.Config
	store       *store.Store
	logger      *slog.Logger
	signer      *TokenSigner
	oidc        *oidc.Provider
	verifier    *oidc.IDTokenVerifier
	oauth       *oauth2.Config
	mu          sync.Mutex
	requests    map[string]authRequest
	codes       map[string]authorizationCode
	hostedCodes map[string]hostedResult
}

func New(ctx context.Context, cfg config.Config, dataStore *store.Store, logger *slog.Logger) (*Service, error) {
	service := &Service{
		cfg: cfg, store: dataStore, logger: logger,
		signer:   NewTokenSigner(cfg.JWTIssuer, cfg.OIDCOrgID, cfg.JWTSecret, cfg.AccessTokenTTL),
		requests: map[string]authRequest{}, codes: map[string]authorizationCode{}, hostedCodes: map[string]hostedResult{},
	}
	if cfg.OIDCIssuerURL != "" {
		provider, err := oidc.NewProvider(ctx, cfg.OIDCIssuerURL)
		if err != nil {
			return nil, fmt.Errorf("initialize OIDC provider: %w", err)
		}
		service.oidc = provider
		service.verifier = provider.Verifier(&oidc.Config{ClientID: cfg.OIDCClientID})
		service.oauth = &oauth2.Config{
			ClientID: cfg.OIDCClientID, ClientSecret: cfg.OIDCClientSecret,
			Endpoint: provider.Endpoint(), RedirectURL: cfg.OIDCRedirectURL,
			Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
		}
	}
	return service, nil
}

func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/auth/providers", s.providers)
	mux.HandleFunc("POST /api/auth/discovery", s.discovery)
	mux.HandleFunc("POST /api/auth/sso/discovery", s.ssoDiscovery)
	mux.HandleFunc("GET /api/auth/sso/{connection}/authorize", s.authorize)
	mux.HandleFunc("GET /api/auth/oidc/callback", s.oidcCallback)
	mux.HandleFunc("POST /api/auth/desktop/callback/poll", s.pollDesktopCallback)
	mux.HandleFunc("POST /api/auth/token", s.exchangeCode)
	mux.HandleFunc("POST /api/auth/email/request-code", s.requestDevCode)
	mux.HandleFunc("POST /api/auth/email/verify-code", s.verifyDevCode)
	mux.HandleFunc("POST /api/auth/refresh", s.refresh)
	mux.Handle("GET /api/me", s.Require(http.HandlerFunc(s.me)))
	mux.Handle("PATCH /api/me/profile", s.Require(http.HandlerFunc(s.patchProfile)))
	mux.Handle("GET /api/auth/account", s.Require(http.HandlerFunc(s.account)))
	mux.Handle("POST /api/auth/account/exchange", s.Require(http.HandlerFunc(s.accountExchange)))
	mux.Handle("GET /api/auth/account/deletion", s.Require(http.HandlerFunc(s.deletionAvailability)))
	mux.Handle("POST /api/auth/logout", s.Require(http.HandlerFunc(s.logout)))
	mux.Handle("GET /api/user/feature-flags", s.Require(http.HandlerFunc(s.featureFlags)))
}

func (s *Service) Signer() *TokenSigner { return s.signer }

func (s *Service) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := web.BearerToken(r)
		claims, err := s.signer.Verify(raw)
		if err != nil {
			web.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "valid bearer token required")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, claims)))
	})
}

func ClaimsFromContext(ctx context.Context) (Claims, bool) {
	claims, ok := ctx.Value(contextKey{}).(Claims)
	return claims, ok
}

func (s *Service) providers(w http.ResponseWriter, _ *http.Request) {
	web.JSON(w, http.StatusOK, map[string]any{
		"region": s.cfg.Region, "attribution": "email", "email": s.cfg.DevLoginCode != "", "phone": false, "social": []string{},
	})
}

func (s *Service) discovery(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if web.DecodeJSON(r, &body, 8<<10) != nil || !strings.Contains(body.Email, "@") {
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "email is required")
		return
	}
	methods := make([]map[string]any, 0, 2)
	if s.oidc != nil && s.emailAllowed(body.Email) {
		methods = append(methods, s.ssoMethod(true))
	}
	if s.cfg.DevLoginCode != "" {
		methods = append(methods, map[string]any{"type": "email_code"})
	}
	web.JSON(w, http.StatusOK, map[string]any{"methods": methods})
}

func (s *Service) ssoDiscovery(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Org string `json:"org"`
	}
	if web.DecodeJSON(r, &body, 8<<10) != nil || strings.TrimSpace(body.Org) == "" {
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "org is required")
		return
	}
	connections := []map[string]any{}
	if s.oidc != nil && s.orgAllowed(body.Org) {
		connections = append(connections, map[string]any{"connectionId": "enterprise", "protocol": "oidc", "connectionName": s.cfg.OIDCConnectionName})
	}
	web.JSON(w, http.StatusOK, map[string]any{"region": s.cfg.Region, "orgName": s.cfg.OIDCOrgName, "connections": connections})
}

func (s *Service) authorize(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil || r.PathValue("connection") != "enterprise" {
		web.Error(w, http.StatusNotFound, "SSO_NOT_CONFIGURED", "SSO connection not configured")
		return
	}
	redirectURI := r.URL.Query().Get("redirect_uri")
	if !s.allowedClientRedirect(redirectURI) {
		web.Error(w, http.StatusBadRequest, "BAD_REDIRECT_URI", "redirect_uri is not allowed")
		return
	}
	challenge := r.URL.Query().Get("code_challenge")
	deviceID := strings.TrimSpace(r.URL.Query().Get("device_id"))
	if challenge == "" || deviceID == "" || r.URL.Query().Get("code_challenge_method") != "S256" {
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "device_id and S256 PKCE are required")
		return
	}
	state := store.RandomToken(24)
	s.mu.Lock()
	s.cleanupLocked()
	s.requests[state] = authRequest{
		RedirectURI: redirectURI, CodeChallenge: challenge,
		ClientState: r.URL.Query().Get("client_state"), DeviceID: deviceID, ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	s.mu.Unlock()
	http.Redirect(w, r, s.oauth.AuthCodeURL(state), http.StatusFound)
}

func (s *Service) oidcCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	s.mu.Lock()
	request, ok := s.requests[state]
	delete(s.requests, state)
	s.mu.Unlock()
	if !ok || request.ExpiresAt.Before(time.Now()) {
		web.Error(w, http.StatusBadRequest, "AUTH_STATE_EXPIRED", "login state expired")
		return
	}
	if providerError := strings.TrimSpace(r.URL.Query().Get("error")); providerError != "" {
		s.finishProviderError(w, r, request, providerError)
		return
	}
	oauthToken, err := s.oauth.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		web.Error(w, http.StatusUnauthorized, "OIDC_EXCHANGE_FAILED", "identity provider exchange failed")
		return
	}
	rawIDToken, ok := oauthToken.Extra("id_token").(string)
	if !ok {
		web.Error(w, http.StatusUnauthorized, "OIDC_ID_TOKEN_MISSING", "identity provider returned no id token")
		return
	}
	idToken, err := s.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		web.Error(w, http.StatusUnauthorized, "OIDC_ID_TOKEN_INVALID", "identity token validation failed")
		return
	}
	var identity struct {
		Subject           string `json:"sub"`
		Email             string `json:"email"`
		EmailVerified     *bool  `json:"email_verified"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idToken.Claims(&identity); err != nil || identity.Subject == "" {
		web.Error(w, http.StatusUnauthorized, "OIDC_CLAIMS_INVALID", "identity claims are invalid")
		return
	}
	if identity.Email == "" {
		identity.Email = identity.PreferredUsername
	}
	if identity.Email == "" || identity.Name == "" {
		if userInfo, infoErr := s.oidc.UserInfo(r.Context(), oauth2.StaticTokenSource(oauthToken)); infoErr == nil {
			var profile struct {
				Name              string `json:"name"`
				PreferredUsername string `json:"preferred_username"`
			}
			_ = userInfo.Claims(&profile)
			if identity.Subject == "" {
				identity.Subject = userInfo.Subject
			}
			if identity.Email == "" {
				identity.Email = userInfo.Email
			}
			if identity.Email == "" {
				identity.Email = profile.PreferredUsername
			}
			if identity.Name == "" {
				identity.Name = profile.Name
			}
		}
	}
	if identity.EmailVerified != nil && !*identity.EmailVerified {
		web.Error(w, http.StatusForbidden, "EMAIL_NOT_VERIFIED", "identity provider email is not verified")
		return
	}
	if !s.emailAllowed(identity.Email) {
		web.Error(w, http.StatusForbidden, "ORG_NOT_ALLOWED", "identity is outside the configured organization")
		return
	}
	user, err := s.store.FindOrCreateUser(s.cfg.OIDCIssuerURL+"|"+identity.Subject, identity.Email, identity.Name)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to persist identity")
		return
	}
	code := store.RandomToken(24)
	s.mu.Lock()
	s.codes[code] = authorizationCode{UserID: user.ID, DeviceID: request.DeviceID, CodeChallenge: request.CodeChallenge, ExpiresAt: time.Now().Add(5 * time.Minute)}
	if s.isHostedRedirect(request.RedirectURI) {
		s.hostedCodes[request.ClientState] = hostedResult{Status: "ok", Code: code, ExpiresAt: time.Now().Add(5 * time.Minute)}
	}
	s.mu.Unlock()
	if s.isHostedRedirect(request.RedirectURI) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = successPage.Execute(w, map[string]string{"Name": user.DisplayName})
		return
	}
	destination, _ := url.Parse(request.RedirectURI)
	query := destination.Query()
	query.Set("code", code)
	query.Set("state", request.ClientState)
	destination.RawQuery = query.Encode()
	http.Redirect(w, r, destination.String(), http.StatusFound)
}

func (s *Service) pollDesktopCallback(w http.ResponseWriter, r *http.Request) {
	var body struct {
		PollSecret string `json:"pollSecret"`
		DeviceID   string `json:"deviceId"`
	}
	if web.DecodeJSON(r, &body, 8<<10) != nil || body.PollSecret == "" {
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "pollSecret is required")
		return
	}
	digest := sha256.Sum256([]byte(body.PollSecret))
	key := base64.RawURLEncoding.EncodeToString(digest[:])
	s.mu.Lock()
	hosted, ok := s.hostedCodes[key]
	if ok {
		delete(s.hostedCodes, key)
	}
	s.mu.Unlock()
	if !ok {
		web.JSON(w, http.StatusOK, map[string]string{"status": "pending"})
		return
	}
	if hosted.ExpiresAt.Before(time.Now()) {
		web.JSON(w, http.StatusOK, map[string]string{"status": "expired"})
		return
	}
	if hosted.Status == "error" {
		web.JSON(w, http.StatusOK, map[string]string{"status": "error", "error": hosted.Error})
		return
	}
	web.JSON(w, http.StatusOK, map[string]string{"status": "ok", "code": hosted.Code})
}

func (s *Service) finishProviderError(w http.ResponseWriter, r *http.Request, request authRequest, providerError string) {
	if s.isHostedRedirect(request.RedirectURI) {
		s.mu.Lock()
		s.hostedCodes[request.ClientState] = hostedResult{Status: "error", Error: providerError, ExpiresAt: time.Now().Add(5 * time.Minute)}
		s.mu.Unlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = errorPage.Execute(w, map[string]string{"Error": providerError})
		return
	}
	destination, _ := url.Parse(request.RedirectURI)
	query := destination.Query()
	query.Set("error", providerError)
	query.Set("state", request.ClientState)
	destination.RawQuery = query.Encode()
	http.Redirect(w, r, destination.String(), http.StatusFound)
}

func (s *Service) exchangeCode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		GrantType    string `json:"grantType"`
		Code         string `json:"code"`
		CodeVerifier string `json:"codeVerifier"`
		DeviceID     string `json:"deviceId"`
	}
	if web.DecodeJSON(r, &body, 16<<10) != nil || body.GrantType != "authorization_code" {
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "authorization code grant required")
		return
	}
	s.mu.Lock()
	code, ok := s.codes[body.Code]
	if ok {
		delete(s.codes, body.Code)
	}
	s.mu.Unlock()
	if !ok || code.ExpiresAt.Before(time.Now()) || !verifyPKCE(code.CodeChallenge, body.CodeVerifier) {
		web.Error(w, http.StatusUnauthorized, "AUTHORIZATION_CODE_INVALID", "authorization code is invalid")
		return
	}
	if body.DeviceID != "" && body.DeviceID != code.DeviceID {
		web.Error(w, http.StatusUnauthorized, "DEVICE_MISMATCH", "authorization code belongs to another device")
		return
	}
	s.issueTokenPair(w, code.UserID, code.DeviceID)
}

func (s *Service) requestDevCode(w http.ResponseWriter, r *http.Request) {
	if s.cfg.DevLoginCode == "" {
		web.Error(w, http.StatusNotFound, "EMAIL_LOGIN_DISABLED", "email login is disabled")
		return
	}
	web.JSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

func (s *Service) verifyDevCode(w http.ResponseWriter, r *http.Request) {
	if s.cfg.DevLoginCode == "" {
		web.Error(w, http.StatusNotFound, "EMAIL_LOGIN_DISABLED", "email login is disabled")
		return
	}
	var body struct {
		Email      string `json:"email"`
		Code       string `json:"code"`
		DeviceID   string `json:"deviceId"`
		ClientType string `json:"clientType"`
		Locale     string `json:"locale"`
	}
	if web.DecodeJSON(r, &body, 8<<10) != nil || body.Code != s.cfg.DevLoginCode || !s.emailAllowed(body.Email) || body.DeviceID == "" {
		web.Error(w, http.StatusUnauthorized, "INVALID_CODE", "verification code is invalid")
		return
	}
	user, err := s.store.FindOrCreateUser("dev|"+strings.ToLower(body.Email), strings.ToLower(body.Email), body.Email)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to persist user")
		return
	}
	s.issueTokenPair(w, user.ID, body.DeviceID)
}

func (s *Service) refresh(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RefreshToken string `json:"refreshToken"`
		DeviceID     string `json:"deviceId"`
	}
	if web.DecodeJSON(r, &body, 16<<10) != nil || body.RefreshToken == "" || body.DeviceID == "" {
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "refreshToken and deviceId are required")
		return
	}
	token, ok, err := s.store.ConsumeRefreshToken(store.TokenHash(body.RefreshToken))
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to rotate refresh token")
		return
	}
	if !ok || token.DeviceID != body.DeviceID {
		web.Error(w, http.StatusUnauthorized, "REFRESH_TOKEN_INVALID", "refresh token is invalid")
		return
	}
	s.issueTokenPair(w, token.UserID, body.DeviceID)
}

func (s *Service) issueTokenPair(w http.ResponseWriter, userID, deviceID string) {
	user, ok := s.store.User(userID)
	if !ok {
		web.Error(w, http.StatusUnauthorized, "USER_NOT_FOUND", "user no longer exists")
		return
	}
	membershipID := s.membershipID(user.ID)
	access, err := s.signer.Issue(user.ID, membershipID, deviceID, user.Email)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to issue access token")
		return
	}
	rawRefresh := store.RandomToken(32)
	if err := s.store.PutRefreshToken(store.RefreshToken{Hash: store.TokenHash(rawRefresh), UserID: user.ID, DeviceID: deviceID, ExpiresAt: time.Now().Add(s.cfg.RefreshTokenTTL).Unix()}); err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to issue refresh token")
		return
	}
	web.JSON(w, http.StatusOK, map[string]any{"status": "ok", "accessToken": access, "refreshToken": rawRefresh, "membership": s.membership(user)})
}

func (s *Service) me(w http.ResponseWriter, r *http.Request) {
	claims, _ := ClaimsFromContext(r.Context())
	user, ok := s.store.User(claims.Subject)
	if !ok {
		web.Error(w, http.StatusNotFound, "USER_NOT_FOUND", "user not found")
		return
	}
	membership := s.membership(user)
	web.JSON(w, http.StatusOK, map[string]any{"membership": membership, "passportId": user.ID, "identities": []Membership{membership}})
}

func (s *Service) patchProfile(w http.ResponseWriter, r *http.Request) {
	claims, _ := ClaimsFromContext(r.Context())
	user, ok := s.store.User(claims.Subject)
	if !ok {
		web.Error(w, http.StatusNotFound, "USER_NOT_FOUND", "user not found")
		return
	}
	var body struct {
		DisplayName *string         `json:"displayName"`
		AvatarURL   json.RawMessage `json:"avatarUrl"`
	}
	if web.DecodeJSON(r, &body, 16<<10) != nil {
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid profile")
		return
	}
	if body.DisplayName != nil && strings.TrimSpace(*body.DisplayName) != "" {
		user.DisplayName = strings.TrimSpace(*body.DisplayName)
	}
	if len(body.AvatarURL) > 0 {
		if string(body.AvatarURL) == "null" {
			user.AvatarURL = ""
		} else {
			var avatarURL string
			if json.Unmarshal(body.AvatarURL, &avatarURL) != nil {
				web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "avatarUrl must be a string or null")
				return
			}
			user.AvatarURL = strings.TrimSpace(avatarURL)
		}
	}
	if err := s.store.UpdateUser(user); err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to update profile")
		return
	}
	web.JSON(w, http.StatusOK, map[string]any{"membership": s.membership(user)})
}

func (s *Service) account(w http.ResponseWriter, r *http.Request) {
	claims, _ := ClaimsFromContext(r.Context())
	user, ok := s.store.User(claims.Subject)
	if !ok {
		web.Error(w, http.StatusNotFound, "USER_NOT_FOUND", "user not found")
		return
	}
	membership := s.membership(user)
	web.JSON(w, http.StatusOK, map[string]any{"memberships": []map[string]any{{
		"id": membership.ID, "passportId": membership.PassportID, "kind": membership.Kind, "role": membership.Role,
		"displayName": membership.DisplayName, "avatarUrl": membership.AvatarURL, "email": membership.Email,
		"orgId": membership.OrgID, "orgName": membership.OrgName, "orgLogoUrl": membership.OrgLogoURL, "orgSlug": s.cfg.OIDCOrgID,
	}}})
}

func (s *Service) accountExchange(w http.ResponseWriter, r *http.Request) {
	claims, _ := ClaimsFromContext(r.Context())
	s.issueTokenPair(w, claims.Subject, claims.DeviceID)
}

func (s *Service) deletionAvailability(w http.ResponseWriter, _ *http.Request) {
	web.JSON(w, http.StatusOK, map[string]any{"available": false, "manualAppleRevocationRequired": false})
}

func (s *Service) logout(w http.ResponseWriter, r *http.Request) {
	claims, _ := ClaimsFromContext(r.Context())
	if err := s.store.DeleteRefreshTokens(claims.Subject, claims.DeviceID); err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to revoke session")
		return
	}
	web.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
func (s *Service) featureFlags(w http.ResponseWriter, _ *http.Request) {
	web.JSON(w, http.StatusOK, map[string]bool{"isCanary": false})
}

func (s *Service) membership(user store.User) Membership {
	email := user.Email
	orgID, orgName := s.cfg.OIDCOrgID, s.cfg.OIDCOrgName
	var avatar *string
	if user.AvatarURL != "" {
		avatar = &user.AvatarURL
	}
	return Membership{
		ID: s.membershipID(user.ID), PassportID: user.ID, Kind: "org", Role: "member", DisplayName: user.DisplayName,
		AvatarURL: avatar, Email: &email, OrgID: &orgID, OrgName: &orgName, OrgLogoURL: nil,
	}
}

func (s *Service) membershipID(userID string) string { return "mem_" + userID }

func (s *Service) ssoMethod(required bool) map[string]any {
	return map[string]any{"type": "sso", "connectionId": "enterprise", "protocol": "oidc", "orgName": s.cfg.OIDCOrgName, "connectionName": s.cfg.OIDCConnectionName, "ssoRequired": required}
}

func (s *Service) emailAllowed(email string) bool {
	if s.cfg.OIDCOrgDomain == "" {
		return strings.Contains(email, "@")
	}
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(email)), "@"+s.cfg.OIDCOrgDomain)
}

func (s *Service) orgAllowed(org string) bool {
	value := strings.ToLower(strings.TrimSpace(org))
	return value == strings.ToLower(s.cfg.OIDCOrgID) || value == strings.ToLower(s.cfg.OIDCOrgName) || value == s.cfg.OIDCOrgDomain
}

func (s *Service) allowedClientRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return false
	}
	if u.Scheme == "cindy" || u.Scheme == "cindycn" || u.Scheme == "cindydev" {
		return true
	}
	if (u.Scheme == "http" || u.Scheme == "https") && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost") {
		return true
	}
	return strings.HasPrefix(raw, s.cfg.PublicBaseURL+"/api/auth/desktop/callback")
}

func (s *Service) isHostedRedirect(raw string) bool {
	return strings.HasPrefix(raw, s.cfg.PublicBaseURL+"/api/auth/desktop/callback")
}

func (s *Service) cleanupLocked() {
	now := time.Now()
	for key, value := range s.requests {
		if value.ExpiresAt.Before(now) {
			delete(s.requests, key)
		}
	}
	for key, value := range s.codes {
		if value.ExpiresAt.Before(now) {
			delete(s.codes, key)
		}
	}
	for key, value := range s.hostedCodes {
		if value.ExpiresAt.Before(now) {
			delete(s.hostedCodes, key)
		}
	}
}

func verifyPKCE(challenge, verifier string) bool {
	if challenge == "" || verifier == "" {
		return false
	}
	digest := sha256.Sum256([]byte(verifier))
	return challenge == base64.RawURLEncoding.EncodeToString(digest[:])
}

var successPage = template.Must(template.New("success").Parse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>登录成功</title><body><main style="font:16px system-ui;max-width:560px;margin:15vh auto;padding:24px"><h1>登录成功</h1><p>{{.Name}}，你可以关闭这个窗口并返回 Cindy。</p></main></body></html>`))
var errorPage = template.Must(template.New("error").Parse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>登录失败</title><body><main style="font:16px system-ui;max-width:560px;margin:15vh auto;padding:24px"><h1>登录未完成</h1><p>身份提供方返回：{{.Error}}</p><p>请关闭窗口并返回 Cindy 重试。</p></main></body></html>`))
