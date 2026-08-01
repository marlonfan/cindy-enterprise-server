package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Claims struct {
	Issuer       string `json:"iss"`
	Subject      string `json:"sub"`
	MembershipID string `json:"mid"`
	DeviceID     string `json:"did"`
	Email        string `json:"email,omitempty"`
	OrgSlug      string `json:"orgSlug,omitempty"`
	IssuedAt     int64  `json:"iat"`
	ExpiresAt    int64  `json:"exp"`
}

type TokenSigner struct {
	issuer  string
	orgSlug string
	secret  []byte
	ttl     time.Duration
}

func NewTokenSigner(issuer, orgSlug, secret string, ttl time.Duration) *TokenSigner {
	return &TokenSigner{issuer: issuer, orgSlug: orgSlug, secret: []byte(secret), ttl: ttl}
}

func (s *TokenSigner) Issue(userID, membershipID, deviceID, email string) (string, error) {
	now := time.Now()
	claims := Claims{
		Issuer: s.issuer, Subject: userID, MembershipID: membershipID,
		DeviceID: deviceID, Email: email, OrgSlug: s.orgSlug, IssuedAt: now.Unix(), ExpiresAt: now.Add(s.ttl).Unix(),
	}
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return unsigned + "." + s.signature(unsigned), nil
}

func (s *TokenSigner) Verify(raw string) (Claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("invalid token shape")
	}
	unsigned := parts[0] + "." + parts[1]
	want, err := base64.RawURLEncoding.DecodeString(s.signature(unsigned))
	if err != nil {
		return Claims{}, err
	}
	got, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(got, want) {
		return Claims{}, errors.New("invalid token signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, err
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Claims{}, err
	}
	if claims.Issuer != s.issuer || claims.Subject == "" || claims.MembershipID == "" || claims.DeviceID == "" {
		return Claims{}, errors.New("invalid token claims")
	}
	if claims.ExpiresAt <= time.Now().Unix() {
		return Claims{}, fmt.Errorf("token expired")
	}
	return claims, nil
}

func (s *TokenSigner) signature(unsigned string) string {
	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write([]byte(unsigned))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
