package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"math/big"
	"net/http"
	netmail "net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/marlonfan/cindy-enterprise-server/internal/mail"
	"github.com/marlonfan/cindy-enterprise-server/internal/web"
)

const (
	defaultEmailCodeTTL             = 10 * time.Minute
	defaultEmailCodeResendInterval  = 42 * time.Second
	defaultEmailCodeMaxAttempts     = 5
	defaultEmailCodeMaxSendsPerHour = 6
)

type emailChallenge struct {
	digest            [sha256.Size]byte
	expiresAt         time.Time
	remainingAttempts int
}

type emailSendState struct {
	nextAllowed time.Time
	windowEnds  time.Time
	sends       int
	pending     bool
}

func (s *Service) emailLoginEnabled() bool {
	return s.emailSender != nil || s.cfg.DevLoginCode != ""
}

func (s *Service) requestEmailCode(w http.ResponseWriter, r *http.Request) {
	if !s.emailLoginEnabled() {
		web.Error(w, http.StatusNotFound, "EMAIL_LOGIN_DISABLED", "email login is disabled")
		return
	}
	var body struct {
		Email  string `json:"email"`
		Locale string `json:"locale"`
	}
	if web.DecodeJSON(r, &body, 8<<10) != nil {
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "valid enterprise email is required")
		return
	}
	email, ok := s.normalizeLoginEmail(body.Email)
	if !ok {
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "valid enterprise email is required")
		return
	}

	if s.emailSender == nil {
		web.JSON(w, http.StatusOK, map[string]string{"status": "sent"})
		return
	}

	now := s.now()
	if retryAfter, allowed := s.reserveEmailSend(email, now); !allowed {
		w.Header().Set("Retry-After", strconv.FormatInt(retrySeconds(retryAfter), 10))
		web.Error(w, http.StatusTooManyRequests, "RATE_LIMITED", "verification code requested too frequently")
		return
	}

	code, err := generateEmailCode()
	if err != nil {
		s.finishEmailSend(email, emailChallenge{}, false)
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to generate verification code")
		return
	}
	ttl := s.emailCodeTTL()
	message, err := mail.RenderVerificationCode(mail.VerificationCodeParams{
		Code: code, ValidityMinutes: validityMinutes(ttl), ProductName: s.cfg.SMTPFromName, SupportAddress: s.cfg.SMTPFromAddress,
	})
	if err != nil {
		s.finishEmailSend(email, emailChallenge{}, false)
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to render verification email")
		return
	}
	if err := s.emailSender.SendVerificationCode(r.Context(), email, message); err != nil {
		s.finishEmailSend(email, emailChallenge{}, false)
		web.Error(w, http.StatusServiceUnavailable, "EMAIL_DELIVERY_FAILED", "verification email could not be delivered")
		return
	}
	challenge := emailChallenge{
		digest: s.emailCodeDigest(email, code), expiresAt: now.Add(ttl), remainingAttempts: s.emailCodeMaxAttempts(),
	}
	s.finishEmailSend(email, challenge, true)
	web.JSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

func (s *Service) verifyEmailCode(w http.ResponseWriter, r *http.Request) {
	if !s.emailLoginEnabled() {
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
	if web.DecodeJSON(r, &body, 8<<10) != nil || strings.TrimSpace(body.DeviceID) == "" {
		web.Error(w, http.StatusUnauthorized, "INVALID_CODE", "verification code is invalid")
		return
	}
	email, ok := s.normalizeLoginEmail(body.Email)
	if !ok {
		web.Error(w, http.StatusUnauthorized, "INVALID_CODE", "verification code is invalid")
		return
	}

	valid := false
	if s.emailSender != nil {
		valid = s.consumeEmailCode(email, strings.TrimSpace(body.Code), s.now())
	} else {
		valid = subtle.ConstantTimeCompare([]byte(strings.TrimSpace(body.Code)), []byte(s.cfg.DevLoginCode)) == 1
	}
	if !valid {
		web.Error(w, http.StatusUnauthorized, "INVALID_CODE", "verification code is invalid")
		return
	}

	user, err := s.store.FindOrCreateUser("dev|"+email, email, email)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to persist user")
		return
	}
	s.issueTokenPair(w, user.ID, strings.TrimSpace(body.DeviceID))
}

func (s *Service) normalizeLoginEmail(raw string) (string, bool) {
	address, err := netmail.ParseAddress(strings.TrimSpace(raw))
	if err != nil || address.Address == "" {
		return "", false
	}
	normalized := strings.ToLower(strings.TrimSpace(address.Address))
	return normalized, s.emailAllowed(normalized)
}

func (s *Service) reserveEmailSend(email string, now time.Time) (time.Duration, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneEmailCodesLocked(now)

	state := s.emailSends[email]
	if state.windowEnds.IsZero() || !now.Before(state.windowEnds) {
		state = emailSendState{windowEnds: now.Add(time.Hour)}
	}
	if state.pending {
		return time.Second, false
	}
	if now.Before(state.nextAllowed) {
		return state.nextAllowed.Sub(now), false
	}
	if state.sends >= s.emailCodeMaxSendsPerHour() {
		return state.windowEnds.Sub(now), false
	}
	state.sends++
	state.nextAllowed = now.Add(s.emailCodeResendInterval())
	state.pending = true
	s.emailSends[email] = state
	return 0, true
}

func (s *Service) finishEmailSend(email string, challenge emailChallenge, delivered bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.emailSends[email]
	state.pending = false
	s.emailSends[email] = state
	if delivered {
		s.emailChallenges[email] = challenge
	}
}

func (s *Service) consumeEmailCode(email, code string, now time.Time) bool {
	digest := s.emailCodeDigest(email, code)
	s.mu.Lock()
	defer s.mu.Unlock()
	challenge, ok := s.emailChallenges[email]
	if !ok || !now.Before(challenge.expiresAt) {
		delete(s.emailChallenges, email)
		return false
	}
	if subtle.ConstantTimeCompare(digest[:], challenge.digest[:]) != 1 {
		challenge.remainingAttempts--
		if challenge.remainingAttempts <= 0 {
			delete(s.emailChallenges, email)
		} else {
			s.emailChallenges[email] = challenge
		}
		return false
	}
	delete(s.emailChallenges, email)
	return true
}

func (s *Service) pruneEmailCodesLocked(now time.Time) {
	for email, challenge := range s.emailChallenges {
		if !now.Before(challenge.expiresAt) {
			delete(s.emailChallenges, email)
		}
	}
	for email, state := range s.emailSends {
		if !state.pending && !now.Before(state.windowEnds) {
			delete(s.emailSends, email)
		}
	}
}

func (s *Service) emailCodeDigest(email, code string) [sha256.Size]byte {
	digest := hmac.New(sha256.New, []byte(s.cfg.JWTSecret))
	_, _ = digest.Write([]byte(email))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(code))
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func (s *Service) emailCodeTTL() time.Duration {
	if s.cfg.EmailCodeTTL <= 0 {
		return defaultEmailCodeTTL
	}
	return s.cfg.EmailCodeTTL
}

func (s *Service) emailCodeResendInterval() time.Duration {
	if s.cfg.EmailCodeResendInterval <= 0 {
		return defaultEmailCodeResendInterval
	}
	return s.cfg.EmailCodeResendInterval
}

func (s *Service) emailCodeMaxAttempts() int {
	if s.cfg.EmailCodeMaxAttempts <= 0 {
		return defaultEmailCodeMaxAttempts
	}
	return s.cfg.EmailCodeMaxAttempts
}

func (s *Service) emailCodeMaxSendsPerHour() int {
	if s.cfg.EmailCodeHourlyLimit <= 0 {
		return defaultEmailCodeMaxSendsPerHour
	}
	return s.cfg.EmailCodeHourlyLimit
}

func generateEmailCode() (string, error) {
	value, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", fmt.Errorf("generate secure verification code: %w", err)
	}
	return fmt.Sprintf("%06d", value.Int64()), nil
}

func validityMinutes(ttl time.Duration) int {
	return int((ttl + time.Minute - 1) / time.Minute)
}

func retrySeconds(duration time.Duration) int64 {
	seconds := int64((duration + time.Second - 1) / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}
