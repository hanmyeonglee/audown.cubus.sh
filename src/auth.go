package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

//go:embed templates/*.html
var authTemplatesFS embed.FS

const (
	challengeTTL      = 5 * time.Minute
	sessionTTL        = 30 * 24 * time.Hour
	maxAuthBodyBytes  = 64 << 10
	maxUserAgentBytes = 256
	tokenByteLen      = 32

	authPageCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

	authRateLimitWindow = time.Minute
	authRateLimitMax    = 30
	authRateLimitMaxIPs = 4096
)

var inviteTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

type webAuthnUser struct {
	id          uuid.UUID
	displayName string
	credentials []webauthn.Credential
}

func (u *webAuthnUser) WebAuthnID() []byte                         { return u.id[:] }
func (u *webAuthnUser) WebAuthnName() string                       { return u.displayName }
func (u *webAuthnUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func toWebAuthnCredential(rec CredentialRecord) webauthn.Credential {
	transports := make([]protocol.AuthenticatorTransport, 0, len(rec.Transport))
	for _, t := range rec.Transport {
		if t != "" {
			transports = append(transports, protocol.AuthenticatorTransport(t))
		}
	}
	var flags webauthn.CredentialFlags
	if len(rec.Flags) > 0 {
		flags = webauthn.NewCredentialFlags(protocol.AuthenticatorFlags(rec.Flags[0]))
	}
	flags.BackupEligible = rec.BackupEligible
	flags.BackupState = rec.BackupState

	return webauthn.Credential{
		ID:              rec.ID,
		PublicKey:       rec.PublicKey,
		AttestationType: rec.AttestationType,
		Transport:       transports,
		Flags:           flags,
		Authenticator: webauthn.Authenticator{
			AAGUID:    rec.AAGUID,
			SignCount: rec.SignCount,
		},
	}
}

func credentialTransportsToStrings(ts []protocol.AuthenticatorTransport) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		if s := string(t); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func credentialFlagsToBytes(f webauthn.CredentialFlags) []byte {
	return []byte{byte(f.ProtocolValue())}
}

type ipRateLimiter struct {
	mu      sync.Mutex
	window  time.Duration
	maxHits int
	maxIPs  int
	hits    map[string]rateWindow
}

type rateWindow struct {
	count int
	reset time.Time
}

func newIPRateLimiter(window time.Duration, maxHits, maxIPs int) *ipRateLimiter {
	return &ipRateLimiter{
		window:  window,
		maxHits: maxHits,
		maxIPs:  maxIPs,
		hits:    make(map[string]rateWindow),
	}
}

func (l *ipRateLimiter) Allow(ip string, now time.Time) bool {
	if l == nil || l.maxHits <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if w, ok := l.hits[ip]; ok {
		if !w.reset.After(now) {
			l.hits[ip] = rateWindow{count: 1, reset: now.Add(l.window)}
			return true
		}
		if w.count >= l.maxHits {
			return false
		}
		w.count++
		l.hits[ip] = w
		return true
	}

	if len(l.hits) >= l.maxIPs {
		for k, w := range l.hits {
			if !w.reset.After(now) {
				delete(l.hits, k)
			}
		}
		if len(l.hits) >= l.maxIPs {
			var oldestKey string
			var oldestReset time.Time
			first := true
			for k, w := range l.hits {
				if first || w.reset.Before(oldestReset) {
					oldestKey = k
					oldestReset = w.reset
					first = false
				}
			}
			if !first {
				delete(l.hits, oldestKey)
			}
		}
	}

	l.hits[ip] = rateWindow{count: 1, reset: now.Add(l.window)}
	return true
}

// AuthService manages Passkey (WebAuthn) enrollment, login, sessions, and CSRF enforcement.
type AuthService struct {
	cfg        Config
	store      Store
	settings   *SettingsStore
	wa         *webauthn.WebAuthn
	nowFn      func() time.Time
	limiter    *ipRateLimiter
	loginTmpl  *template.Template
	inviteTmpl *template.Template
}

// NewAuthService constructs a validated AuthService with WebAuthn derived strictly from cfg.PublicBaseURL.
func NewAuthService(cfg Config, store Store, settings *SettingsStore) (*AuthService, error) {
	if store == nil {
		return nil, errors.New("auth store must not be nil")
	}
	if settings == nil {
		return nil, errors.New("auth settings store must not be nil")
	}
	if cfg.RPID == "" || cfg.RPOrigin == "" {
		return nil, errors.New("invalid WebAuthn RP configuration")
	}

	requireRK := true
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: "AuDown",
		RPOrigins:     []string{cfg.RPOrigin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			RequireResidentKey: &requireRK,
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			UserVerification:   protocol.VerificationPreferred,
		},
		ExtensionsUnsolicitedOutputPolicy: protocol.UnsolicitedOutputPolicyIgnore,
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    challengeTTL,
				TimeoutUVD: challengeTTL,
			},
			Registration: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    challengeTTL,
				TimeoutUVD: challengeTTL,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("init webauthn: %w", err)
	}

	loginTmpl, err := template.ParseFS(authTemplatesFS, "templates/login.html")
	if err != nil {
		return nil, fmt.Errorf("parse login template: %w", err)
	}
	inviteTmpl, err := template.ParseFS(authTemplatesFS, "templates/invite.html")
	if err != nil {
		return nil, fmt.Errorf("parse invite template: %w", err)
	}

	return &AuthService{
		cfg:        cfg,
		store:      store,
		settings:   settings,
		wa:         wa,
		nowFn:      func() time.Time { return time.Now().UTC() },
		limiter:    newIPRateLimiter(authRateLimitWindow, authRateLimitMax, authRateLimitMaxIPs),
		loginTmpl:  loginTmpl,
		inviteTmpl: inviteTmpl,
	}, nil
}

func (a *AuthService) now() time.Time {
	if a.nowFn != nil {
		return a.nowFn().UTC()
	}
	return time.Now().UTC()
}

func newRandomToken() (string, error) {
	b := make([]byte, tokenByteLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashToken(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

func sanitizeUserAgent(ua string) string {
	ua = strings.TrimSpace(ua)
	if len(ua) > maxUserAgentBytes {
		ua = ua[:maxUserAgentBytes]
	}
	var b strings.Builder
	b.Grow(len(ua))
	for i := range len(ua) {
		c := ua[i]
		if c >= 0x20 && c < 0x7f {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func clientIPKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peerIP, peerErr := netip.ParseAddr(strings.TrimSpace(host))
	if peerErr == nil {
		peerIP = peerIP.Unmap()
		// Trust a single X-Real-IP header only when the direct TCP peer is a trusted local/private proxy.
		if peerIP.IsLoopback() || peerIP.IsPrivate() {
			xriVals := r.Header.Values("X-Real-IP")
			if len(xriVals) == 1 {
				if forwarded, err := netip.ParseAddr(strings.TrimSpace(xriVals[0])); err == nil {
					return forwarded.Unmap().String()
				}
			}
		}
		return peerIP.String()
	}
	return "unknown"
}

// CheckCSRF enforces Origin == PUBLIC_BASE_URL (or Sec-Fetch-Site: same-origin when Origin is absent)
// on all state-changing requests.
func (a *AuthService) CheckCSRF(r *http.Request) bool {
	secSites := r.Header.Values("Sec-Fetch-Site")
	if len(secSites) > 1 {
		return false
	}
	secSite := ""
	if len(secSites) == 1 {
		secSite = strings.ToLower(strings.TrimSpace(secSites[0]))
		if secSite != "" && secSite != "same-origin" {
			return false
		}
	}

	origins := r.Header.Values("Origin")
	if len(origins) > 1 {
		return false
	}
	if len(origins) == 1 {
		origin := strings.TrimSpace(origins[0])
		return origin != "" && origin == a.cfg.RPOrigin
	}

	return secSite == "same-origin"
}

func (a *AuthService) setSessionCookie(w http.ResponseWriter, rawToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.cfg.SessionCookieName,
		Value:    rawToken,
		Path:     "/",
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   a.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *AuthService) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.cfg.SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   a.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

// Authenticate validates the session cookie, enforces active user status, and slides the
// 30-day rolling expiration in PostgreSQL and the browser cookie.
func (a *AuthService) Authenticate(w http.ResponseWriter, r *http.Request) (SessionWithUser, bool) {
	cookie, err := r.Cookie(a.cfg.SessionCookieName)
	if err != nil || cookie == nil {
		return SessionWithUser{}, false
	}
	rawToken := strings.TrimSpace(cookie.Value)
	if len(rawToken) < 16 || len(rawToken) > 128 {
		a.clearSessionCookie(w)
		return SessionWithUser{}, false
	}

	now := a.now()
	swu, err := a.store.TouchSession(r.Context(), hashToken(rawToken), now, now.Add(sessionTTL))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			a.clearSessionCookie(w)
		}
		return SessionWithUser{}, false
	}
	a.setSessionCookie(w, rawToken)
	return swu, true
}

func writeAuthPageHeaders(w http.ResponseWriter, referrerPolicy string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", referrerPolicy)
	w.Header().Set("Content-Security-Policy", authPageCSP)
}

func writeAuthJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	data, err := json.Marshal(v)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"failed to encode JSON response"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func writeAuthError(w http.ResponseWriter, status int, msg string) {
	writeAuthJSON(w, status, map[string]string{"error": msg})
}

func (a *AuthService) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := a.Authenticate(w, r); ok {
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	var buf bytes.Buffer
	if err := a.loginTmpl.Execute(&buf, nil); err != nil {
		slog.Error("Render login template failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeAuthPageHeaders(w, "same-origin")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(buf.Bytes())
	}
}

type invitePageData struct {
	Invalid     bool
	DisplayName string
}

func (a *AuthService) handleInvitePage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.limiter.Allow(clientIPKey(r), a.now()) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	token := strings.TrimSpace(r.PathValue("token"))
	data := invitePageData{Invalid: true}
	status := http.StatusGone

	if inviteTokenPattern.MatchString(token) {
		inv, err := a.store.GetInviteByTokenHash(r.Context(), hashToken(token))
		if err == nil && inv.UsedAt == nil && inv.ExpiresAt.After(a.now()) {
			data = invitePageData{
				Invalid:     false,
				DisplayName: inv.DisplayName,
			}
			status = http.StatusOK
		}
	}

	var buf bytes.Buffer
	if err := a.inviteTmpl.Execute(&buf, data); err != nil {
		slog.Error("Render invite template failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	// Referrer-Policy: no-referrer ensures the invite token in the URL is never leaked.
	writeAuthPageHeaders(w, "no-referrer")
	w.WriteHeader(status)
	if r.Method == http.MethodGet {
		_, _ = w.Write(buf.Bytes())
	}
}

func (a *AuthService) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeAuthError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	requireAuth := a.settings.IsRequireAuth()
	if swu, ok := a.Authenticate(w, r); ok {
		writeAuthJSON(w, http.StatusOK, map[string]any{
			"authenticated": true,
			"require_auth":  requireAuth,
			"user": map[string]any{
				"id":           swu.User.ID.String(),
				"display_name": swu.User.DisplayName,
			},
		})
		return
	}
	if requireAuth {
		writeAuthJSON(w, http.StatusUnauthorized, map[string]any{
			"authenticated": false,
			"require_auth":  true,
			"error":         "authentication required",
		})
		return
	}
	writeAuthJSON(w, http.StatusOK, map[string]any{
		"authenticated": false,
		"require_auth":  false,
	})
}

func (a *AuthService) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeAuthError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !a.CheckCSRF(r) {
		writeAuthError(w, http.StatusForbidden, "invalid request origin")
		return
	}

	var rawToken string
	if c, err := r.Cookie(a.cfg.SessionCookieName); err == nil && c != nil {
		rawToken = strings.TrimSpace(c.Value)
	}
	requireAuth := a.settings.IsRequireAuth()
	if rawToken == "" || len(rawToken) < 16 || len(rawToken) > 128 {
		a.clearSessionCookie(w)
		if requireAuth {
			writeAuthError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		writeAuthJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}

	wasValid, err := a.store.DeleteSessionByTokenHash(r.Context(), hashToken(rawToken), a.now())
	if err != nil {
		slog.Error("Delete session on logout failed", "error", err)
		writeAuthError(w, http.StatusInternalServerError, "로그아웃 처리에 실패했습니다.")
		return
	}
	a.clearSessionCookie(w)
	if requireAuth && !wasValid {
		writeAuthError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	writeAuthJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func decodeAuthJSONBody(w http.ResponseWriter, r *http.Request, dst any) (int, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAuthBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return http.StatusRequestEntityTooLarge, errors.New("request body too large")
		}
		return http.StatusBadRequest, errors.New("failed to read request body")
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return http.StatusBadRequest, errors.New("request body must be a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return http.StatusBadRequest, errors.New("invalid JSON payload")
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return http.StatusBadRequest, errors.New("trailing JSON tokens")
	}
	return 0, nil
}

type registerBeginRequest struct {
	Token string `json:"token"`
}

func (a *AuthService) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeAuthError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !a.CheckCSRF(r) {
		writeAuthError(w, http.StatusForbidden, "invalid request origin")
		return
	}
	now := a.now()
	if !a.limiter.Allow(clientIPKey(r), now) {
		w.Header().Set("Retry-After", "60")
		writeAuthError(w, http.StatusTooManyRequests, "요청이 너무 많습니다. 잠시 후 다시 시도해주세요.")
		return
	}

	var req registerBeginRequest
	if status, err := decodeAuthJSONBody(w, r, &req); err != nil {
		writeAuthError(w, status, err.Error())
		return
	}
	token := strings.TrimSpace(req.Token)
	if !inviteTokenPattern.MatchString(token) {
		writeAuthError(w, http.StatusGone, "초대 링크가 만료되었거나 이미 사용되었습니다.")
		return
	}

	inv, err := a.store.GetInviteByTokenHash(r.Context(), hashToken(token))
	if err != nil || inv.UsedAt != nil || !inv.ExpiresAt.After(now) {
		writeAuthError(w, http.StatusGone, "초대 링크가 만료되었거나 이미 사용되었습니다.")
		return
	}

	provisionalUser := &webAuthnUser{
		id:          uuid.New(),
		displayName: inv.DisplayName,
	}
	creation, sessionData, err := a.wa.BeginRegistration(provisionalUser)
	if err != nil {
		slog.Error("WebAuthn BeginRegistration failed", "error", err)
		writeAuthError(w, http.StatusInternalServerError, "패스키 등록을 시작할 수 없습니다.")
		return
	}

	sessionBytes, err := json.Marshal(sessionData)
	if err != nil {
		slog.Error("Marshal WebAuthn register session failed", "error", err)
		writeAuthError(w, http.StatusInternalServerError, "패스키 등록을 시작할 수 없습니다.")
		return
	}
	challengeID, err := newRandomToken()
	if err != nil {
		slog.Error("Generate challenge ID failed", "error", err)
		writeAuthError(w, http.StatusInternalServerError, "패스키 등록을 시작할 수 없습니다.")
		return
	}

	inviteID := inv.ID
	if err := a.store.CreateChallenge(r.Context(), ChallengeRecord{
		ID:          challengeID,
		Purpose:     ChallengePurposeRegister,
		InviteID:    &inviteID,
		SessionData: sessionBytes,
		ExpiresAt:   now.Add(challengeTTL),
	}); err != nil {
		slog.Error("Persist register challenge failed", "error", err)
		writeAuthError(w, http.StatusInternalServerError, "패스키 등록을 시작할 수 없습니다.")
		return
	}

	writeAuthJSON(w, http.StatusOK, map[string]any{
		"challenge_id": challengeID,
		"publicKey":    creation.Response,
	})
}

type registerFinishRequest struct {
	ChallengeID string          `json:"challenge_id"`
	Token       string          `json:"token"`
	Credential  json.RawMessage `json:"credential"`
}

func (a *AuthService) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeAuthError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !a.CheckCSRF(r) {
		writeAuthError(w, http.StatusForbidden, "invalid request origin")
		return
	}
	now := a.now()
	if !a.limiter.Allow(clientIPKey(r), now) {
		w.Header().Set("Retry-After", "60")
		writeAuthError(w, http.StatusTooManyRequests, "요청이 너무 많습니다. 잠시 후 다시 시도해주세요.")
		return
	}

	var req registerFinishRequest
	if status, err := decodeAuthJSONBody(w, r, &req); err != nil {
		writeAuthError(w, status, err.Error())
		return
	}
	challengeID := strings.TrimSpace(req.ChallengeID)
	token := strings.TrimSpace(req.Token)
	if challengeID == "" || len(challengeID) > 128 || !inviteTokenPattern.MatchString(token) || len(bytes.TrimSpace(req.Credential)) == 0 {
		writeAuthError(w, http.StatusBadRequest, "잘못된 등록 요청입니다.")
		return
	}

	// Atomically consume single-use challenge before verifying attestation.
	ch, err := a.store.ConsumeChallenge(r.Context(), challengeID, ChallengePurposeRegister, now)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeAuthError(w, http.StatusBadRequest, "등록 요청이 만료되었거나 이미 처리되었습니다. 다시 시도해주세요.")
			return
		}
		slog.Error("Consume register challenge failed", "error", err)
		writeAuthError(w, http.StatusInternalServerError, "패스키 등록에 실패했습니다.")
		return
	}
	if ch.InviteID == nil {
		writeAuthError(w, http.StatusBadRequest, "유효하지 않은 등록 요청입니다.")
		return
	}

	tokenHash := hashToken(token)
	inv, err := a.store.GetInviteByTokenHash(r.Context(), tokenHash)
	if err != nil || inv.ID != *ch.InviteID || inv.UsedAt != nil || !inv.ExpiresAt.After(now) {
		writeAuthError(w, http.StatusGone, "초대 링크가 만료되었거나 이미 사용되었습니다.")
		return
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal(ch.SessionData, &sessionData); err != nil {
		slog.Error("Unmarshal register session data failed", "error", err)
		writeAuthError(w, http.StatusInternalServerError, "패스키 등록에 실패했습니다.")
		return
	}
	userID, err := uuid.FromBytes(sessionData.UserID)
	if err != nil {
		writeAuthError(w, http.StatusBadRequest, "유효하지 않은 사용자 식별자입니다.")
		return
	}

	parsedResp, err := protocol.ParseCredentialCreationResponseBytes(req.Credential)
	if err != nil {
		writeAuthError(w, http.StatusBadRequest, "패스키 응답 형식이 올바르지 않습니다.")
		return
	}

	provisionalUser := &webAuthnUser{
		id:          userID,
		displayName: inv.DisplayName,
	}
	cred, err := a.wa.CreateCredential(provisionalUser, sessionData, parsedResp)
	if err != nil {
		slog.Warn("WebAuthn CreateCredential rejected", "error", err)
		writeAuthError(w, http.StatusBadRequest, "패스키 등록 확인에 실패했습니다. 다시 시도해주세요.")
		return
	}
	if len(cred.ID) == 0 || len(cred.PublicKey) == 0 {
		writeAuthError(w, http.StatusBadRequest, "패스키 자격 증명이 비어 있습니다.")
		return
	}

	rawSessionToken, err := newRandomToken()
	if err != nil {
		slog.Error("Generate session token failed", "error", err)
		writeAuthError(w, http.StatusInternalServerError, "세션 생성에 실패했습니다.")
		return
	}

	err = a.store.CompleteInviteRegistration(r.Context(), CompleteInviteRegistrationParams{
		InviteID:        inv.ID,
		InviteTokenHash: tokenHash,
		User: UserRecord{
			ID:          userID,
			DisplayName: inv.DisplayName,
			Status:      UserStatusActive,
			CreatedAt:   now,
		},
		Credential: CredentialRecord{
			ID:              cred.ID,
			UserID:          userID,
			PublicKey:       cred.PublicKey,
			AttestationType: cred.AttestationType,
			Transport:       credentialTransportsToStrings(cred.Transport),
			Flags:           credentialFlagsToBytes(cred.Flags),
			AAGUID:          cred.Authenticator.AAGUID,
			SignCount:       cred.Authenticator.SignCount,
			BackupEligible:  cred.Flags.BackupEligible,
			BackupState:     cred.Flags.BackupState,
			CreatedAt:       now,
		},
		Session: SessionRecord{
			ID:         uuid.New(),
			TokenHash:  hashToken(rawSessionToken),
			UserID:     userID,
			UserAgent:  sanitizeUserAgent(r.UserAgent()),
			CreatedAt:  now,
			LastSeenAt: now,
			ExpiresAt:  now.Add(sessionTTL),
		},
		Now: now,
	})
	if err != nil {
		if errors.Is(err, ErrInviteInvalid) {
			writeAuthError(w, http.StatusGone, "초대 링크가 만료되었거나 이미 사용되었습니다.")
			return
		}
		if errors.Is(err, ErrConflict) {
			writeAuthError(w, http.StatusConflict, "이미 등록된 패스키입니다.")
			return
		}
		slog.Error("Complete invite registration failed", "error", err)
		writeAuthError(w, http.StatusInternalServerError, "패스키 저장에 실패했습니다.")
		return
	}

	a.setSessionCookie(w, rawSessionToken)
	writeAuthJSON(w, http.StatusOK, map[string]any{
		"user": map[string]any{
			"id":           userID.String(),
			"display_name": inv.DisplayName,
		},
	})
}

func (a *AuthService) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeAuthError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !a.CheckCSRF(r) {
		writeAuthError(w, http.StatusForbidden, "invalid request origin")
		return
	}
	now := a.now()
	if !a.limiter.Allow(clientIPKey(r), now) {
		w.Header().Set("Retry-After", "60")
		writeAuthError(w, http.StatusTooManyRequests, "요청이 너무 많습니다. 잠시 후 다시 시도해주세요.")
		return
	}

	// Drain optional small body (empty or {}).
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeAuthError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeAuthError(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	if trimmed := bytes.TrimSpace(body); len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("{}")) {
		writeAuthError(w, http.StatusBadRequest, "login begin expects an empty body or {}")
		return
	}

	assertion, sessionData, err := a.wa.BeginDiscoverableLogin()
	if err != nil {
		slog.Error("WebAuthn BeginDiscoverableLogin failed", "error", err)
		writeAuthError(w, http.StatusInternalServerError, "로그인을 시작할 수 없습니다.")
		return
	}

	sessionBytes, err := json.Marshal(sessionData)
	if err != nil {
		slog.Error("Marshal WebAuthn login session failed", "error", err)
		writeAuthError(w, http.StatusInternalServerError, "로그인을 시작할 수 없습니다.")
		return
	}
	challengeID, err := newRandomToken()
	if err != nil {
		slog.Error("Generate login challenge ID failed", "error", err)
		writeAuthError(w, http.StatusInternalServerError, "로그인을 시작할 수 없습니다.")
		return
	}

	if err := a.store.CreateChallenge(r.Context(), ChallengeRecord{
		ID:          challengeID,
		Purpose:     ChallengePurposeLogin,
		InviteID:    nil,
		SessionData: sessionBytes,
		ExpiresAt:   now.Add(challengeTTL),
	}); err != nil {
		slog.Error("Persist login challenge failed", "error", err)
		writeAuthError(w, http.StatusInternalServerError, "로그인을 시작할 수 없습니다.")
		return
	}

	writeAuthJSON(w, http.StatusOK, map[string]any{
		"challenge_id": challengeID,
		"publicKey":    assertion.Response,
	})
}

type loginFinishRequest struct {
	ChallengeID string          `json:"challenge_id"`
	Credential  json.RawMessage `json:"credential"`
}

func (a *AuthService) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeAuthError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !a.CheckCSRF(r) {
		writeAuthError(w, http.StatusForbidden, "invalid request origin")
		return
	}
	now := a.now()
	if !a.limiter.Allow(clientIPKey(r), now) {
		w.Header().Set("Retry-After", "60")
		writeAuthError(w, http.StatusTooManyRequests, "요청이 너무 많습니다. 잠시 후 다시 시도해주세요.")
		return
	}

	var req loginFinishRequest
	if status, err := decodeAuthJSONBody(w, r, &req); err != nil {
		writeAuthError(w, status, err.Error())
		return
	}
	challengeID := strings.TrimSpace(req.ChallengeID)
	if challengeID == "" || len(challengeID) > 128 || len(bytes.TrimSpace(req.Credential)) == 0 {
		writeAuthError(w, http.StatusBadRequest, "잘못된 로그인 요청입니다.")
		return
	}

	// Atomically consume single-use challenge before verifying assertion.
	ch, err := a.store.ConsumeChallenge(r.Context(), challengeID, ChallengePurposeLogin, now)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeAuthError(w, http.StatusBadRequest, "로그인 요청이 만료되었거나 이미 처리되었습니다. 다시 시도해주세요.")
			return
		}
		slog.Error("Consume login challenge failed", "error", err)
		writeAuthError(w, http.StatusInternalServerError, "로그인 처리에 실패했습니다.")
		return
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal(ch.SessionData, &sessionData); err != nil {
		slog.Error("Unmarshal login session data failed", "error", err)
		writeAuthError(w, http.StatusInternalServerError, "로그인 처리에 실패했습니다.")
		return
	}

	parsedResp, err := protocol.ParseCredentialRequestResponseBytes(req.Credential)
	if err != nil {
		writeAuthError(w, http.StatusBadRequest, "패스키 응답 형식이 올바르지 않습니다.")
		return
	}

	var matchedUser UserRecord
	discoverableHandler := func(rawID, userHandle []byte) (webauthn.User, error) {
		if len(rawID) == 0 || len(userHandle) != 16 {
			return nil, ErrNotFound
		}
		u, c, lookupErr := a.store.GetUserAndCredentialByCredentialID(r.Context(), rawID)
		if lookupErr != nil {
			return nil, lookupErr
		}
		if subtle.ConstantTimeCompare(u.ID[:], userHandle) != 1 {
			return nil, ErrNotFound
		}
		matchedUser = u
		return &webAuthnUser{
			id:          u.ID,
			displayName: u.DisplayName,
			credentials: []webauthn.Credential{toWebAuthnCredential(c)},
		}, nil
	}

	_, cred, err := a.wa.ValidatePasskeyLogin(discoverableHandler, sessionData, parsedResp)
	if err != nil {
		slog.Warn("WebAuthn ValidatePasskeyLogin rejected", "error", err)
		writeAuthError(w, http.StatusUnauthorized, "패스키 인증에 실패했습니다. 다시 시도해주세요.")
		return
	}
	// Check disabled status only after cryptographic signature verification succeeds
	// so unauthenticated callers cannot probe account status via 403 vs 401.
	if matchedUser.Status != UserStatusActive {
		writeAuthError(w, http.StatusForbidden, "비활성화된 계정입니다. 관리자에게 문의해주세요.")
		return
	}
	if cred.Authenticator.CloneWarning {
		slog.Warn("WebAuthn clone warning detected", "user_id", matchedUser.ID.String())
		writeAuthError(w, http.StatusUnauthorized, "보안 이상이 감지되어 로그인할 수 없습니다. 관리자에게 문의해주세요.")
		return
	}

	rawSessionToken, err := newRandomToken()
	if err != nil {
		slog.Error("Generate session token on login failed", "error", err)
		writeAuthError(w, http.StatusInternalServerError, "세션 생성에 실패했습니다.")
		return
	}

	if err := a.store.CompleteLogin(r.Context(), CompleteLoginParams{
		UserID:         matchedUser.ID,
		CredentialID:   cred.ID,
		Flags:          credentialFlagsToBytes(cred.Flags),
		SignCount:      cred.Authenticator.SignCount,
		BackupEligible: cred.Flags.BackupEligible,
		BackupState:    cred.Flags.BackupState,
		Session: SessionRecord{
			ID:         uuid.New(),
			TokenHash:  hashToken(rawSessionToken),
			UserID:     matchedUser.ID,
			UserAgent:  sanitizeUserAgent(r.UserAgent()),
			CreatedAt:  now,
			LastSeenAt: now,
			ExpiresAt:  now.Add(sessionTTL),
		},
		Now: now,
	}); err != nil {
		if errors.Is(err, ErrUserDisabled) {
			writeAuthError(w, http.StatusForbidden, "비활성화된 계정입니다. 관리자에게 문의해주세요.")
			return
		}
		if errors.Is(err, ErrCloneWarning) {
			slog.Warn("WebAuthn concurrent clone warning detected", "user_id", matchedUser.ID.String())
			writeAuthError(w, http.StatusUnauthorized, "보안 이상이 감지되어 로그인할 수 없습니다. 관리자에게 문의해주세요.")
			return
		}
		slog.Error("Complete login failed", "error", err)
		writeAuthError(w, http.StatusInternalServerError, "로그인 저장에 실패했습니다.")
		return
	}

	a.setSessionCookie(w, rawSessionToken)
	writeAuthJSON(w, http.StatusOK, map[string]any{
		"user": map[string]any{
			"id":           matchedUser.ID.String(),
			"display_name": matchedUser.DisplayName,
		},
	})
}

func isBrowserNavigationRequest(r *http.Request) bool {
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Dest")), "document") ||
		strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Mode")), "navigate") {
		return true
	}
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html")
}
