package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
)

// virtualPasskey simulates a real FIDO2/WebAuthn ES256 discoverable authenticator for tests.
type virtualPasskey struct {
	key        *ecdsa.PrivateKey
	credID     []byte
	userHandle []byte
	rpID       string
	origin     string
	signCount  uint32
}

func newVirtualPasskey(t *testing.T, rpID, origin string) *virtualPasskey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		t.Fatalf("generate credID: %v", err)
	}
	return &virtualPasskey{
		key:    priv,
		credID: credID,
		rpID:   rpID,
		origin: origin,
	}
}

func (v *virtualPasskey) cosePublicKey(t *testing.T) []byte {
	t.Helper()
	xBytes := make([]byte, 32)
	yBytes := make([]byte, 32)
	v.key.PublicKey.X.FillBytes(xBytes)
	v.key.PublicKey.Y.FillBytes(yBytes)
	// COSE_Key map for EC2 / ES256 / P-256: {1: 2, 3: -7, -1: 1, -2: x, -3: y}
	coseMap := map[int]any{
		1:  2,
		3:  -7,
		-1: 1,
		-2: xBytes,
		-3: yBytes,
	}
	out, err := cbor.Marshal(coseMap)
	if err != nil {
		t.Fatalf("marshal COSE key: %v", err)
	}
	return out
}

func (v *virtualPasskey) makeRegistrationPayload(t *testing.T, challengeB64 string, userHandle []byte, signCount uint32, originOverride string) json.RawMessage {
	t.Helper()
	v.userHandle = append([]byte(nil), userHandle...)
	v.signCount = signCount

	origin := v.origin
	if originOverride != "" {
		origin = originOverride
	}

	clientData, err := json.Marshal(map[string]any{
		"type":      "webauthn.create",
		"challenge": challengeB64,
		"origin":    origin,
	})
	if err != nil {
		t.Fatalf("marshal clientData: %v", err)
	}

	rpHash := sha256.Sum256([]byte(v.rpID))
	// Flags: UP(0x01) | UV(0x04) | BE(0x08) | BS(0x10) | AT(0x40)
	flags := byte(0x01 | 0x04 | 0x08 | 0x10 | 0x40)

	var authData bytes.Buffer
	authData.Write(rpHash[:])
	authData.WriteByte(flags)
	var sc [4]byte
	binary.BigEndian.PutUint32(sc[:], signCount)
	authData.Write(sc[:])
	// AAGUID (16 zero bytes)
	authData.Write(make([]byte, 16))
	// CredID length (2 bytes big-endian) + CredID
	var idLen [2]byte
	binary.BigEndian.PutUint16(idLen[:], uint16(len(v.credID)))
	authData.Write(idLen[:])
	authData.Write(v.credID)
	authData.Write(v.cosePublicKey(t))

	attObj, err := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData.Bytes(),
	})
	if err != nil {
		t.Fatalf("marshal attestationObject: %v", err)
	}

	idB64 := base64.RawURLEncoding.EncodeToString(v.credID)
	payload, err := json.Marshal(map[string]any{
		"id":                     idB64,
		"rawId":                  idB64,
		"type":                   "public-key",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"attestationObject": base64.RawURLEncoding.EncodeToString(attObj),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
			"transports":        []string{"internal"},
		},
	})
	if err != nil {
		t.Fatalf("marshal registration payload: %v", err)
	}
	return payload
}

func (v *virtualPasskey) makeAssertionPayload(t *testing.T, challengeB64 string, signCount uint32, originOverride string, userHandleOverride []byte) json.RawMessage {
	t.Helper()
	origin := v.origin
	if originOverride != "" {
		origin = originOverride
	}
	uh := v.userHandle
	if userHandleOverride != nil {
		uh = userHandleOverride
	}

	clientData, err := json.Marshal(map[string]any{
		"type":      "webauthn.get",
		"challenge": challengeB64,
		"origin":    origin,
	})
	if err != nil {
		t.Fatalf("marshal clientData: %v", err)
	}

	rpHash := sha256.Sum256([]byte(v.rpID))
	// Flags: UP(0x01) | UV(0x04) | BE(0x08) | BS(0x10)
	flags := byte(0x01 | 0x04 | 0x08 | 0x10)

	var authData bytes.Buffer
	authData.Write(rpHash[:])
	authData.WriteByte(flags)
	var sc [4]byte
	binary.BigEndian.PutUint32(sc[:], signCount)
	authData.Write(sc[:])

	clientDataHash := sha256.Sum256(clientData)
	signedMsg := append(append([]byte(nil), authData.Bytes()...), clientDataHash[:]...)
	digest := sha256.Sum256(signedMsg)
	sig, err := ecdsa.SignASN1(rand.Reader, v.key, digest[:])
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}

	idB64 := base64.RawURLEncoding.EncodeToString(v.credID)
	payload, err := json.Marshal(map[string]any{
		"id":                     idB64,
		"rawId":                  idB64,
		"type":                   "public-key",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"authenticatorData": base64.RawURLEncoding.EncodeToString(authData.Bytes()),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
			"signature":         base64.RawURLEncoding.EncodeToString(sig),
			"userHandle":        base64.RawURLEncoding.EncodeToString(uh),
		},
	})
	if err != nil {
		t.Fatalf("marshal assertion payload: %v", err)
	}
	return payload
}

type authTestHarness struct {
	pubDir   string
	cfg      Config
	store    *memoryStore
	settings *SettingsStore
	auth     *AuthService
	app      *appServer
	admin    *AdminServer
	pubH     http.Handler
	adminH   http.Handler
	now      time.Time
	nowMu    sync.Mutex
}

func newAuthTestHarness(t *testing.T, publicBaseURL string) *authTestHarness {
	t.Helper()
	pubDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(pubDir, "index.html"), []byte("<html><body>AuDown Home</body></html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(pubDir, "static", "js"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pubDir, "static", "js", "app.js"), []byte("console.log('ok');"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pubDir, "manifest.webmanifest"), []byte(`{"name":"AuDown"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pubDir, "favicon.ico"), []byte("ico"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pubDir, "sw.js"), []byte("// sw"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(mapEnv(map[string]string{
		"PUBLIC_DIR_NAME": pubDir,
		"PUBLIC_BASE_URL": publicBaseURL,
		"ADMIN_API_TOKEN": testAdminToken,
	}))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	mem := newMemoryStore()
	st := NewSettingsStoreWithStore(mem)
	authSrv, err := NewAuthService(cfg, mem, st)
	if err != nil {
		t.Fatalf("NewAuthService: %v", err)
	}
	adminSrv, err := NewAdminServer(st, mem, cfg.PublicBaseURL, cfg.AdminAPIToken, nil)
	if err != nil {
		t.Fatalf("NewAdminServer: %v", err)
	}

	h := &authTestHarness{
		pubDir:   pubDir,
		cfg:      cfg,
		store:    mem,
		settings: st,
		auth:     authSrv,
		admin:    adminSrv,
		now:      time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC),
	}
	clockFn := func() time.Time {
		h.nowMu.Lock()
		defer h.nowMu.Unlock()
		return h.now
	}
	authSrv.nowFn = clockFn
	adminSrv.nowFn = clockFn

	h.app = newAppServer(pubDir, st, authSrv, func(_ context.Context, outputPattern, _, audioFormat, _, _, _ string) error {
		return os.WriteFile(filepath.Join(filepath.Dir(outputPattern), "track."+audioFormat), []byte("audio"), 0o600)
	})
	h.pubH = h.app.handler()
	h.adminH = adminSrv.Handler()
	return h
}

func (h *authTestHarness) advance(d time.Duration) {
	h.nowMu.Lock()
	h.now = h.now.Add(d)
	h.nowMu.Unlock()
}

func (h *authTestHarness) createInvite(t *testing.T, displayName string, ttlHours int) (string, string) {
	t.Helper()
	body := map[string]any{"display_name": displayName, "created_by": "operator"}
	if ttlHours > 0 {
		body["ttl_hours"] = ttlHours
	}
	rec := doAdminReq(t, h.adminH, http.MethodPost, "/admin/v1/invites", "127.0.0.1:41001", testAdminToken, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create invite status %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Invite    InviteView `json:"invite"`
		InviteURL string     `json:"invite_url"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal create invite: %v", err)
	}
	prefix := h.cfg.PublicBaseURL + "/invite/"
	if !strings.HasPrefix(resp.InviteURL, prefix) {
		t.Fatalf("unexpected invite_url %q", resp.InviteURL)
	}
	return resp.Invite.ID.String(), strings.TrimPrefix(resp.InviteURL, prefix)
}

func (h *authTestHarness) enrollPasskey(t *testing.T, token string, pk *virtualPasskey, initialSignCount uint32) (*http.Cookie, string) {
	t.Helper()
	// 1. Register begin
	beginBody, _ := json.Marshal(map[string]string{"token": token})
	beginReq := httptest.NewRequest(http.MethodPost, "/auth/passkey/register/begin", bytes.NewReader(beginBody))
	beginReq.Header.Set("Content-Type", "application/json")
	beginReq.Header.Set("Origin", h.cfg.RPOrigin)
	beginRec := httptest.NewRecorder()
	h.pubH.ServeHTTP(beginRec, beginReq)
	if beginRec.Code != http.StatusOK {
		t.Fatalf("register/begin failed: %d %s", beginRec.Code, beginRec.Body.String())
	}

	var beginResp struct {
		ChallengeID string `json:"challenge_id"`
		PublicKey   struct {
			Challenge string `json:"challenge"`
			User      struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(beginRec.Body.Bytes(), &beginResp); err != nil {
		t.Fatalf("unmarshal register/begin: %v", err)
	}
	userHandle, err := base64.RawURLEncoding.DecodeString(beginResp.PublicKey.User.ID)
	if err != nil {
		t.Fatalf("decode user.id: %v", err)
	}

	credPayload := pk.makeRegistrationPayload(t, beginResp.PublicKey.Challenge, userHandle, initialSignCount, "")
	finishBody, _ := json.Marshal(map[string]any{
		"challenge_id": beginResp.ChallengeID,
		"token":        token,
		"credential":   credPayload,
	})
	finishReq := httptest.NewRequest(http.MethodPost, "/auth/passkey/register/finish", bytes.NewReader(finishBody))
	finishReq.Header.Set("Content-Type", "application/json")
	finishReq.Header.Set("Origin", h.cfg.RPOrigin)
	finishReq.Header.Set("User-Agent", "Mozilla/5.0 Safari")
	finishRec := httptest.NewRecorder()
	h.pubH.ServeHTTP(finishRec, finishReq)
	if finishRec.Code != http.StatusOK {
		t.Fatalf("register/finish failed: %d %s", finishRec.Code, finishRec.Body.String())
	}

	var finishResp struct {
		User struct {
			ID          string `json:"id"`
			DisplayName string `json:"display_name"`
		} `json:"user"`
	}
	if err := json.Unmarshal(finishRec.Body.Bytes(), &finishResp); err != nil {
		t.Fatalf("unmarshal register/finish: %v", err)
	}
	cookies := finishRec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != h.cfg.SessionCookieName {
		t.Fatalf("expected session cookie %q, got %+v", h.cfg.SessionCookieName, cookies)
	}
	return cookies[0], finishResp.User.ID
}

func TestConfigPublicBaseURLAndSecretRedaction(t *testing.T) {
	cfgHTTPS, err := LoadConfig(mapEnv(map[string]string{
		"PUBLIC_BASE_URL": "https://AUDOWN.CUBUS.SH:443/",
		"DATABASE_URL":    "postgresql://svc_audown:super-secret-db-pw@postgres:5432/svc_audown",
		"DB_BROKER_URL":   "http://db-broker:8080/v1/database",
	}))
	if err != nil {
		t.Fatalf("LoadConfig HTTPS failed: %v", err)
	}
	if cfgHTTPS.PublicBaseURL != "https://audown.cubus.sh" || cfgHTTPS.RPID != "audown.cubus.sh" || !cfgHTTPS.CookieSecure || cfgHTTPS.SessionCookieName != SessionCookieNameHTTPS {
		t.Fatalf("unexpected HTTPS config: %+v", cfgHTTPS)
	}
	if strings.Contains(cfgHTTPS.String(), "super-secret-db-pw") || strings.Contains(cfgHTTPS.LogValue().String(), "super-secret-db-pw") {
		t.Fatal("DATABASE_URL password leaked in Config.String or Config.LogValue")
	}

	cfgHTTP, err := LoadConfig(mapEnv(map[string]string{}))
	if err != nil {
		t.Fatalf("LoadConfig default HTTP failed: %v", err)
	}
	if cfgHTTP.PublicBaseURL != "http://localhost:8080" || cfgHTTP.RPID != "localhost" || cfgHTTP.CookieSecure || cfgHTTP.SessionCookieName != SessionCookieNameHTTP {
		t.Fatalf("unexpected HTTP config: %+v", cfgHTTP)
	}
	// Regression: default config must initialize NewAuthService (go-webauthn rejects IP-literal RPIDs).
	if _, err := NewAuthService(cfgHTTP, newMemoryStore(), NewSettingsStore()); err != nil {
		t.Fatalf("NewAuthService failed with default config: %v", err)
	}

	for _, bad := range []string{
		"ftp://audown.cubus.sh",
		"http://127.0.0.1:8080",
		"https://[::1]:8080",
		"https://audown.cubus.sh/subpath",
		"https://user:pass@audown.cubus.sh",
		"https://audown.cubus.sh?foo=bar",
		"https://audown.cubus.sh#frag",
		"not-a-url",
	} {
		if _, _, _, err := ParsePublicBaseURL(bad); err == nil {
			t.Fatalf("expected ParsePublicBaseURL to reject %q", bad)
		}
	}
}

func TestDBBrokerResolveRetryFailFastAndMigrationEmbed(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		n := attempts.Add(1)
		if n < 3 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"database":"svc_audown","username":"svc_audown","password":"secret","host":"postgres","port":5432,"url":"postgresql://svc_audown:secret@postgres:5432/svc_audown?sslmode=disable"}`))
	}))
	defer srv.Close()

	sleeps := 0
	got, err := fetchFromBroker(context.Background(), srv.URL, srv.Client(), func(time.Duration) {
		sleeps++
	})
	if err != nil {
		t.Fatalf("expected retry success, got %v", err)
	}
	if !strings.Contains(got, "svc_audown") || attempts.Load() != 3 || sleeps != 2 {
		t.Fatalf("unexpected retry stats: got=%q attempts=%d sleeps=%d", got, attempts.Load(), sleeps)
	}

	// Fail fast on 400, 403, 409 without retrying.
	for _, code := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusConflict} {
		var calls atomic.Int32
		failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.WriteHeader(code)
		}))
		_, err := fetchFromBroker(context.Background(), failSrv.URL, failSrv.Client(), func(time.Duration) {
			t.Fatalf("must not sleep on status %d", code)
		})
		failSrv.Close()
		if err == nil || calls.Load() != 1 {
			t.Fatalf("status %d: expected single fail-fast attempt, err=%v calls=%d", code, err, calls.Load())
		}
	}

	// Standalone fallback when DB_BROKER_URL is unset.
	dsn, err := ResolveDatabaseURL(context.Background(), Config{DatabaseURL: "postgresql://dev:dev@127.0.0.1:5432/dev"}, nil)
	if err != nil || dsn != "postgresql://dev:dev@127.0.0.1:5432/dev" {
		t.Fatalf("unexpected standalone fallback: (%q, %v)", dsn, err)
	}
	if _, err := ResolveDatabaseURL(context.Background(), Config{}, nil); err == nil {
		t.Fatal("expected error when both DB_BROKER_URL and DATABASE_URL are empty")
	}

	// Embedded migration file exists and defines all required tables.
	sqlBytes, err := migrationsFS.ReadFile("migrations/001_init.sql")
	if err != nil {
		t.Fatalf("read embedded 001_init.sql: %v", err)
	}
	sqlText := string(sqlBytes)
	for _, tbl := range []string{"users", "invite_tokens", "webauthn_credentials", "webauthn_challenges", "sessions", "app_settings"} {
		if !strings.Contains(sqlText, "CREATE TABLE IF NOT EXISTS "+tbl) {
			t.Fatalf("001_init.sql missing table %s", tbl)
		}
	}
}

func TestPasskeyEndToEndEnrollmentLoginSessionCSRFAndAdminAPI(t *testing.T) {
	h := newAuthTestHarness(t, "https://audown.cubus.sh")

	// 1. Public routes remain accessible when require_auth=true; protected routes redirect/401.
	for _, pubPath := range []string{"/healthz", "/login", "/static/js/app.js", "/manifest.webmanifest", "/favicon.ico", "/sw.js"} {
		req := httptest.NewRequest(http.MethodGet, pubPath, nil)
		rec := httptest.NewRecorder()
		h.pubH.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("public route %s returned %d, want 200", pubPath, rec.Code)
		}
	}

	for _, protectedPath := range []string{"/", "/index.html"} {
		req := httptest.NewRequest(http.MethodGet, protectedPath, nil)
		rec := httptest.NewRecorder()
		h.pubH.ServeHTTP(rec, req)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
			t.Fatalf("protected %s returned %d loc=%q, want 303 /login", protectedPath, rec.Code, rec.Header().Get("Location"))
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("protected %s missing Cache-Control: no-store", protectedPath)
		}
	}

	// Unauthenticated GET /auth/me -> 401 when require_auth=true.
	meUnauth := httptest.NewRecorder()
	h.pubH.ServeHTTP(meUnauth, httptest.NewRequest(http.MethodGet, "/auth/me", nil))
	if meUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated /auth/me, got %d", meUnauth.Code)
	}

	// Unauthenticated POST /download with valid Origin -> 401 for API, 303 /login for browser nav.
	dlAPIReq := httptest.NewRequest(http.MethodPost, "/download", strings.NewReader(url.Values{"url": {"https://youtu.be/dQw4w9WgXcQ"}}.Encode()))
	dlAPIReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	dlAPIReq.Header.Set("Origin", h.cfg.RPOrigin)
	dlAPIRec := httptest.NewRecorder()
	h.pubH.ServeHTTP(dlAPIRec, dlAPIReq)
	if dlAPIRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated API POST /download, got %d", dlAPIRec.Code)
	}

	dlNavReq := httptest.NewRequest(http.MethodPost, "/download", strings.NewReader(url.Values{"url": {"https://youtu.be/dQw4w9WgXcQ"}}.Encode()))
	dlNavReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	dlNavReq.Header.Set("Origin", h.cfg.RPOrigin)
	dlNavReq.Header.Set("Sec-Fetch-Dest", "document")
	dlNavRec := httptest.NewRecorder()
	h.pubH.ServeHTTP(dlNavRec, dlNavReq)
	if dlNavRec.Code != http.StatusSeeOther || dlNavRec.Header().Get("Location") != "/login" {
		t.Fatalf("expected 303 /login for unauthenticated browser POST /download, got %d %q", dlNavRec.Code, dlNavRec.Header().Get("Location"))
	}

	// 2. Create Enrollment Invite with HTML-special display_name to verify escaping.
	inviteID, rawToken := h.createInvite(t, `엄마 <script>alert(1)</script>`, 24)

	// GET /invite/{token} renders escaped display_name, no-referrer, no-store, and does NOT consume invite.
	for i := range 2 {
		invReq := httptest.NewRequest(http.MethodGet, "/invite/"+rawToken, nil)
		invRec := httptest.NewRecorder()
		h.pubH.ServeHTTP(invRec, invReq)
		if invRec.Code != http.StatusOK {
			t.Fatalf("GET /invite attempt %d returned %d", i+1, invRec.Code)
		}
		if invRec.Header().Get("Referrer-Policy") != "no-referrer" || invRec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("invite page missing strict security headers: %v", invRec.Header())
		}
		body := invRec.Body.String()
		if strings.Contains(body, "<script>alert(1)</script>") {
			t.Fatal("XSS: unescaped display_name in invite page")
		}
		if !strings.Contains(body, "이 기기로 시작하기 (패스키 등록)") {
			t.Fatal("invite page missing primary Korean CTA button")
		}
	}

	// Verify log path redaction never logs raw invite token.
	if got := sanitizePathForLog("/invite/" + rawToken); got != "/invite/[redacted]" {
		t.Fatalf("expected /invite/[redacted], got %q", got)
	}

	// GET /admin/v1/invites must NEVER leak rawToken.
	listInvRec := doAdminReq(t, h.adminH, http.MethodGet, "/admin/v1/invites", "127.0.0.1:41002", testAdminToken, nil)
	if listInvRec.Code != http.StatusOK || strings.Contains(listInvRec.Body.String(), rawToken) {
		t.Fatalf("GET /admin/v1/invites leaked raw token or failed: %d %s", listInvRec.Code, listInvRec.Body.String())
	}

	// 3. Enroll Passkey via invite -> creates user, credential, and __Host-audown_session cookie.
	pk := newVirtualPasskey(t, h.cfg.RPID, h.cfg.RPOrigin)
	sessCookie, userID := h.enrollPasskey(t, rawToken, pk, 1)
	if !sessCookie.HttpOnly || !sessCookie.Secure || sessCookie.SameSite != http.SameSiteLaxMode || sessCookie.Path != "/" || sessCookie.MaxAge != int(sessionTTL.Seconds()) {
		t.Fatalf("unexpected HTTPS session cookie flags: %+v", sessCookie)
	}

	// Consumed invite cannot be viewed or reused; admin cannot delete already-used invite (409).
	usedInvRec := httptest.NewRecorder()
	h.pubH.ServeHTTP(usedInvRec, httptest.NewRequest(http.MethodGet, "/invite/"+rawToken, nil))
	if usedInvRec.Code != http.StatusGone {
		t.Fatalf("expected 410 on consumed invite GET, got %d", usedInvRec.Code)
	}
	delUsedRec := doAdminReq(t, h.adminH, http.MethodDelete, "/admin/v1/invites/"+inviteID, "127.0.0.1:41002", testAdminToken, nil)
	if delUsedRec.Code != http.StatusConflict {
		t.Fatalf("expected 409 deleting used invite, got %d: %s", delUsedRec.Code, delUsedRec.Body.String())
	}

	// 4. Authenticated requests succeed on GET /, GET /auth/me, and POST /download.
	rootReq := httptest.NewRequest(http.MethodGet, "/", nil)
	rootReq.AddCookie(sessCookie)
	rootRec := httptest.NewRecorder()
	h.pubH.ServeHTTP(rootRec, rootReq)
	if rootRec.Code != http.StatusOK || !strings.Contains(rootRec.Body.String(), "AuDown Home") {
		t.Fatalf("authenticated GET / failed: %d", rootRec.Code)
	}

	meReq := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	meReq.AddCookie(sessCookie)
	meRec := httptest.NewRecorder()
	h.pubH.ServeHTTP(meRec, meReq)
	if meRec.Code != http.StatusOK || !strings.Contains(meRec.Body.String(), `"authenticated":true`) {
		t.Fatalf("authenticated GET /auth/me failed: %d %s", meRec.Code, meRec.Body.String())
	}

	dlAuthReq := httptest.NewRequest(http.MethodPost, "/download", strings.NewReader(url.Values{"url": {"https://youtu.be/dQw4w9WgXcQ"}}.Encode()))
	dlAuthReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	dlAuthReq.Header.Set("Origin", h.cfg.RPOrigin)
	dlAuthReq.AddCookie(sessCookie)
	dlAuthRec := httptest.NewRecorder()
	h.pubH.ServeHTTP(dlAuthRec, dlAuthReq)
	if dlAuthRec.Code != http.StatusOK {
		t.Fatalf("authenticated POST /download failed: %d %s", dlAuthRec.Code, dlAuthRec.Body.String())
	}

	// 5. Rolling 30-day session expiration: advance 20 days -> still valid and slides +30d -> advance 20 more days -> still valid -> advance 31 days -> expired!
	h.advance(20 * 24 * time.Hour)
	slideReq := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	slideReq.AddCookie(sessCookie)
	slideRec := httptest.NewRecorder()
	h.pubH.ServeHTTP(slideRec, slideReq)
	if slideRec.Code != http.StatusOK {
		t.Fatalf("expected session valid at day 20, got %d", slideRec.Code)
	}
	h.advance(20 * 24 * time.Hour)
	slideReq2 := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	slideReq2.AddCookie(sessCookie)
	slideRec2 := httptest.NewRecorder()
	h.pubH.ServeHTTP(slideRec2, slideReq2)
	if slideRec2.Code != http.StatusOK {
		t.Fatalf("expected rolled session valid at day 40 (20d after slide), got %d", slideRec2.Code)
	}
	h.advance(31 * 24 * time.Hour)
	expiredReq := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	expiredReq.AddCookie(sessCookie)
	expiredRec := httptest.NewRecorder()
	h.pubH.ServeHTTP(expiredRec, expiredReq)
	if expiredRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected session expired after 31 days idle, got %d", expiredRec.Code)
	}

	// 6. Discoverable Passkey Login (signCount 1 -> 2) + Clone Warning detection (replaying signCount 2 -> rejected!).
	loginBeginReq := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/begin", strings.NewReader("{}"))
	loginBeginReq.Header.Set("Origin", h.cfg.RPOrigin)
	loginBeginRec := httptest.NewRecorder()
	h.pubH.ServeHTTP(loginBeginRec, loginBeginReq)
	if loginBeginRec.Code != http.StatusOK {
		t.Fatalf("login/begin failed: %d %s", loginBeginRec.Code, loginBeginRec.Body.String())
	}
	var loginBegin struct {
		ChallengeID string `json:"challenge_id"`
		PublicKey   struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	_ = json.Unmarshal(loginBeginRec.Body.Bytes(), &loginBegin)

	assertPayload := pk.makeAssertionPayload(t, loginBegin.PublicKey.Challenge, 2, "", nil)
	loginFinishBody, _ := json.Marshal(map[string]any{
		"challenge_id": loginBegin.ChallengeID,
		"credential":   assertPayload,
	})
	loginFinishReq := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/finish", bytes.NewReader(loginFinishBody))
	loginFinishReq.Header.Set("Content-Type", "application/json")
	loginFinishReq.Header.Set("Origin", h.cfg.RPOrigin)
	loginFinishRec := httptest.NewRecorder()
	h.pubH.ServeHTTP(loginFinishRec, loginFinishReq)
	if loginFinishRec.Code != http.StatusOK {
		t.Fatalf("login/finish failed: %d %s", loginFinishRec.Code, loginFinishRec.Body.String())
	}
	loginCookie := loginFinishRec.Result().Cookies()[0]

	// Challenge replay on same challenge_id MUST fail.
	replayReq := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/finish", bytes.NewReader(loginFinishBody))
	replayReq.Header.Set("Content-Type", "application/json")
	replayReq.Header.Set("Origin", h.cfg.RPOrigin)
	replayRec := httptest.NewRecorder()
	h.pubH.ServeHTTP(replayRec, replayReq)
	if replayRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on challenge replay, got %d", replayRec.Code)
	}

	// Clone warning: fresh challenge, same signCount=2 (<= stored 2) -> rejected 401!
	cloneBeginReq := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/begin", strings.NewReader("{}"))
	cloneBeginReq.Header.Set("Origin", h.cfg.RPOrigin)
	cloneBeginRec := httptest.NewRecorder()
	h.pubH.ServeHTTP(cloneBeginRec, cloneBeginReq)
	var cloneBegin struct {
		ChallengeID string `json:"challenge_id"`
		PublicKey   struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	_ = json.Unmarshal(cloneBeginRec.Body.Bytes(), &cloneBegin)
	cloneBody, _ := json.Marshal(map[string]any{
		"challenge_id": cloneBegin.ChallengeID,
		"credential":   pk.makeAssertionPayload(t, cloneBegin.PublicKey.Challenge, 2, "", nil),
	})
	cloneReq := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/finish", bytes.NewReader(cloneBody))
	cloneReq.Header.Set("Content-Type", "application/json")
	cloneReq.Header.Set("Origin", h.cfg.RPOrigin)
	cloneRec := httptest.NewRecorder()
	h.pubH.ServeHTTP(cloneRec, cloneReq)
	if cloneRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on clone warning (signCount 2 <= 2), got %d %s", cloneRec.Code, cloneRec.Body.String())
	}

	// 7. Admin API user listing, session revocation, disable user (revokes sessions & blocks login), delete user.
	usersRec := doAdminReq(t, h.adminH, http.MethodGet, "/admin/v1/users", "127.0.0.1:41003", testAdminToken, nil)
	if usersRec.Code != http.StatusOK {
		t.Fatalf("GET /admin/v1/users failed: %d %s", usersRec.Code, usersRec.Body.String())
	}
	var usersList struct {
		Users []UserSummary `json:"users"`
	}
	_ = json.Unmarshal(usersRec.Body.Bytes(), &usersList)
	if len(usersList.Users) != 1 || usersList.Users[0].ID.String() != userID ||
		usersList.Users[0].Username != usersList.Users[0].DisplayName ||
		usersList.Users[0].ActiveSessions != 1 {
		t.Fatalf("unexpected users list: %+v", usersList.Users)
	}

	// Disabling user immediately deletes sessions!
	disableRec := doAdminReq(t, h.adminH, http.MethodPatch, "/admin/v1/users/"+userID, "127.0.0.1:41003", testAdminToken, map[string]string{"status": "disabled"})
	if disableRec.Code != http.StatusOK {
		t.Fatalf("disable user failed: %d %s", disableRec.Code, disableRec.Body.String())
	}
	checkDisabledReq := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	checkDisabledReq.AddCookie(loginCookie)
	checkDisabledRec := httptest.NewRecorder()
	h.pubH.ServeHTTP(checkDisabledRec, checkDisabledReq)
	if checkDisabledRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected disabled user's session invalidated, got %d", checkDisabledRec.Code)
	}

	// Disabled user cannot log in (403 Forbidden).
	disBeginReq := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/begin", strings.NewReader("{}"))
	disBeginReq.Header.Set("Origin", h.cfg.RPOrigin)
	disBeginRec := httptest.NewRecorder()
	h.pubH.ServeHTTP(disBeginRec, disBeginReq)
	var disBegin struct {
		ChallengeID string `json:"challenge_id"`
		PublicKey   struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	_ = json.Unmarshal(disBeginRec.Body.Bytes(), &disBegin)
	disFinBody, _ := json.Marshal(map[string]any{
		"challenge_id": disBegin.ChallengeID,
		"credential":   pk.makeAssertionPayload(t, disBegin.PublicKey.Challenge, 3, "", nil),
	})
	disFinReq := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/finish", bytes.NewReader(disFinBody))
	disFinReq.Header.Set("Content-Type", "application/json")
	disFinReq.Header.Set("Origin", h.cfg.RPOrigin)
	disFinRec := httptest.NewRecorder()
	h.pubH.ServeHTTP(disFinRec, disFinReq)
	if disFinRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for disabled user login, got %d %s", disFinRec.Code, disFinRec.Body.String())
	}

	// Re-enable user, login again, test DELETE /admin/v1/users/{id}/sessions, then logout, then DELETE /admin/v1/users/{id}.
	enableRec := doAdminReq(t, h.adminH, http.MethodPatch, "/admin/v1/users/"+userID, "127.0.0.1:41003", testAdminToken, map[string]string{"status": "active"})
	if enableRec.Code != http.StatusOK {
		t.Fatalf("re-enable user failed: %d", enableRec.Code)
	}
	enBeginReq := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/begin", strings.NewReader("{}"))
	enBeginReq.Header.Set("Origin", h.cfg.RPOrigin)
	enBeginRec := httptest.NewRecorder()
	h.pubH.ServeHTTP(enBeginRec, enBeginReq)
	var enBegin struct {
		ChallengeID string `json:"challenge_id"`
		PublicKey   struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	_ = json.Unmarshal(enBeginRec.Body.Bytes(), &enBegin)
	enFinBody, _ := json.Marshal(map[string]any{
		"challenge_id": enBegin.ChallengeID,
		"credential":   pk.makeAssertionPayload(t, enBegin.PublicKey.Challenge, 4, "", nil),
	})
	enFinReq := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/finish", bytes.NewReader(enFinBody))
	enFinReq.Header.Set("Content-Type", "application/json")
	enFinReq.Header.Set("Origin", h.cfg.RPOrigin)
	enFinRec := httptest.NewRecorder()
	h.pubH.ServeHTTP(enFinRec, enFinReq)
	if enFinRec.Code != http.StatusOK {
		t.Fatalf("login after re-enable failed: %d %s", enFinRec.Code, enFinRec.Body.String())
	}
	freshCookie := enFinRec.Result().Cookies()[0]

	// POST /auth/logout clears session and emits only ONE Set-Cookie header (clearing cookie).
	logoutReq := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	logoutReq.Header.Set("Origin", h.cfg.RPOrigin)
	logoutReq.AddCookie(freshCookie)
	logoutRec := httptest.NewRecorder()
	h.pubH.ServeHTTP(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusOK {
		t.Fatalf("logout failed: %d %s", logoutRec.Code, logoutRec.Body.String())
	}
	logoutCookies := logoutRec.Result().Cookies()
	if len(logoutCookies) != 1 || logoutCookies[0].MaxAge != -1 || logoutCookies[0].Value != "" {
		t.Fatalf("expected single clearing Set-Cookie on logout, got %+v", logoutCookies)
	}

	// Revoke sessions endpoint on existing user + delete user.
	revRec := doAdminReq(t, h.adminH, http.MethodDelete, "/admin/v1/users/"+userID+"/sessions", "127.0.0.1:41003", testAdminToken, nil)
	if revRec.Code != http.StatusOK {
		t.Fatalf("revoke sessions failed: %d %s", revRec.Code, revRec.Body.String())
	}
	delUserRec := doAdminReq(t, h.adminH, http.MethodDelete, "/admin/v1/users/"+userID, "127.0.0.1:41003", testAdminToken, nil)
	if delUserRec.Code != http.StatusOK {
		t.Fatalf("delete user failed: %d %s", delUserRec.Code, delUserRec.Body.String())
	}
	delAgainRec := doAdminReq(t, h.adminH, http.MethodDelete, "/admin/v1/users/"+userID, "127.0.0.1:41003", testAdminToken, nil)
	if delAgainRec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 deleting missing user, got %d", delAgainRec.Code)
	}
}

func TestSyncedPasskeyZeroSignCountAndInviteConcurrencyRace(t *testing.T) {
	h := newAuthTestHarness(t, "https://audown.cubus.sh")

	// 1. Synced passkey (signCount 0 -> 0) must succeed!
	_, tok := h.createInvite(t, "Synced User", 24)
	pk := newVirtualPasskey(t, h.cfg.RPID, h.cfg.RPOrigin)
	h.enrollPasskey(t, tok, pk, 0)

	loginBeginReq := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/begin", strings.NewReader("{}"))
	loginBeginReq.Header.Set("Origin", h.cfg.RPOrigin)
	loginBeginRec := httptest.NewRecorder()
	h.pubH.ServeHTTP(loginBeginRec, loginBeginReq)
	var lb struct {
		ChallengeID string `json:"challenge_id"`
		PublicKey   struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	_ = json.Unmarshal(loginBeginRec.Body.Bytes(), &lb)

	body, _ := json.Marshal(map[string]any{
		"challenge_id": lb.ChallengeID,
		"credential":   pk.makeAssertionPayload(t, lb.PublicKey.Challenge, 0, "", nil),
	})
	finReq := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/finish", bytes.NewReader(body))
	finReq.Header.Set("Content-Type", "application/json")
	finReq.Header.Set("Origin", h.cfg.RPOrigin)
	finRec := httptest.NewRecorder()
	h.pubH.ServeHTTP(finRec, finReq)
	if finRec.Code != http.StatusOK {
		t.Fatalf("expected synced passkey signCount 0->0 login to succeed, got %d %s", finRec.Code, finRec.Body.String())
	}

	// 2. Concurrent invite consumption race: two clients begin with the same invite token and finish concurrently -> ONLY ONE succeeds!
	_, raceTok := h.createInvite(t, "Race User", 24)
	type preparedReg struct {
		body []byte
	}
	var preps [2]preparedReg
	for i := range 2 {
		bBody, _ := json.Marshal(map[string]string{"token": raceTok})
		bReq := httptest.NewRequest(http.MethodPost, "/auth/passkey/register/begin", bytes.NewReader(bBody))
		bReq.Header.Set("Content-Type", "application/json")
		bReq.Header.Set("Origin", h.cfg.RPOrigin)
		bRec := httptest.NewRecorder()
		h.pubH.ServeHTTP(bRec, bReq)
		if bRec.Code != http.StatusOK {
			t.Fatalf("race begin %d failed: %d", i, bRec.Code)
		}
		var br struct {
			ChallengeID string `json:"challenge_id"`
			PublicKey   struct {
				Challenge string `json:"challenge"`
				User      struct {
					ID string `json:"id"`
				} `json:"user"`
			} `json:"publicKey"`
		}
		_ = json.Unmarshal(bRec.Body.Bytes(), &br)
		uh, _ := base64.RawURLEncoding.DecodeString(br.PublicKey.User.ID)
		rpk := newVirtualPasskey(t, h.cfg.RPID, h.cfg.RPOrigin)
		fBody, _ := json.Marshal(map[string]any{
			"challenge_id": br.ChallengeID,
			"token":        raceTok,
			"credential":   rpk.makeRegistrationPayload(t, br.PublicKey.Challenge, uh, 0, ""),
		})
		preps[i] = preparedReg{body: fBody}
	}

	var (
		wg        sync.WaitGroup
		successes atomic.Int32
		failures  atomic.Int32
	)
	startCh := make(chan struct{})
	for i := range 2 {
		wg.Add(1)
		go func(payload []byte) {
			defer wg.Done()
			<-startCh
			req := httptest.NewRequest(http.MethodPost, "/auth/passkey/register/finish", bytes.NewReader(payload))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", h.cfg.RPOrigin)
			rec := httptest.NewRecorder()
			h.pubH.ServeHTTP(rec, req)
			if rec.Code == http.StatusOK {
				successes.Add(1)
			} else {
				failures.Add(1)
			}
		}(preps[i].body)
	}
	close(startCh)
	wg.Wait()

	if successes.Load() != 1 || failures.Load() != 1 {
		t.Fatalf("invite race must allow exactly 1 winner: successes=%d failures=%d", successes.Load(), failures.Load())
	}
}

func TestCSRFGuardAndChallengeExpiryAndAdminInviteValidation(t *testing.T) {
	h := newAuthTestHarness(t, "https://audown.cubus.sh")

	// CSRF rejection cases on state-changing routes.
	csrfBadCases := []struct {
		name    string
		headers map[string]string
	}{
		{"missing headers", map[string]string{}},
		{"wrong origin", map[string]string{"Origin": "https://evil.example"}},
		{"null origin", map[string]string{"Origin": "null"}},
		{"http downgrade origin", map[string]string{"Origin": "http://audown.cubus.sh"}},
		{"cross-site sec-fetch-site", map[string]string{"Origin": h.cfg.RPOrigin, "Sec-Fetch-Site": "cross-site"}},
		{"same-site sec-fetch-site without origin", map[string]string{"Sec-Fetch-Site": "same-site"}},
	}
	for _, route := range []string{"/download", "/auth/logout", "/auth/passkey/login/begin", "/auth/passkey/register/begin"} {
		for _, tc := range csrfBadCases {
			t.Run(route+"_"+tc.name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodPost, route, strings.NewReader("{}"))
				for k, v := range tc.headers {
					req.Header.Set(k, v)
				}
				rec := httptest.NewRecorder()
				h.pubH.ServeHTTP(rec, req)
				if rec.Code != http.StatusForbidden {
					t.Fatalf("%s (%s): expected 403, got %d", route, tc.name, rec.Code)
				}
			})
		}
	}

	// Challenge TTL (5 min): expire challenge before finish -> rejected 400.
	_, tok := h.createInvite(t, "TTL Test", 24)
	bBody, _ := json.Marshal(map[string]string{"token": tok})
	bReq := httptest.NewRequest(http.MethodPost, "/auth/passkey/register/begin", bytes.NewReader(bBody))
	bReq.Header.Set("Sec-Fetch-Site", "same-origin")
	bRec := httptest.NewRecorder()
	h.pubH.ServeHTTP(bRec, bReq)
	if bRec.Code != http.StatusOK {
		t.Fatalf("begin failed: %d", bRec.Code)
	}
	var br struct {
		ChallengeID string `json:"challenge_id"`
		PublicKey   struct {
			Challenge string `json:"challenge"`
			User      struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	_ = json.Unmarshal(bRec.Body.Bytes(), &br)
	uh, _ := base64.RawURLEncoding.DecodeString(br.PublicKey.User.ID)
	pk := newVirtualPasskey(t, h.cfg.RPID, h.cfg.RPOrigin)

	h.advance(6 * time.Minute)
	fBody, _ := json.Marshal(map[string]any{
		"challenge_id": br.ChallengeID,
		"token":        tok,
		"credential":   pk.makeRegistrationPayload(t, br.PublicKey.Challenge, uh, 0, ""),
	})
	fReq := httptest.NewRequest(http.MethodPost, "/auth/passkey/register/finish", bytes.NewReader(fBody))
	fReq.Header.Set("Origin", h.cfg.RPOrigin)
	fRec := httptest.NewRecorder()
	h.pubH.ServeHTTP(fRec, fReq)
	if fRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on expired challenge, got %d %s", fRec.Code, fRec.Body.String())
	}

	// Admin invite validation + delete unused invite (200) + delete unknown (404).
	for _, bad := range []string{
		`{"display_name":""}`,
		`{"display_name":"ok","ttl_hours":0}`,
		`{"display_name":"ok","ttl_hours":721}`,
		`{"display_name":"ok","unknown":1}`,
		`{"display_name":"bad\nname"}`,
	} {
		rec := doAdminReq(t, h.adminH, http.MethodPost, "/admin/v1/invites", "127.0.0.1:41004", testAdminToken, bad)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invite payload %s, got %d", bad, rec.Code)
		}
	}

	unusedID, _ := h.createInvite(t, "Revoke Me", 1)
	delOK := doAdminReq(t, h.adminH, http.MethodDelete, "/admin/v1/invites/"+unusedID, "127.0.0.1:41004", testAdminToken, nil)
	if delOK.Code != http.StatusOK {
		t.Fatalf("expected 200 deleting unused invite, got %d %s", delOK.Code, delOK.Body.String())
	}
	del404 := doAdminReq(t, h.adminH, http.MethodDelete, "/admin/v1/invites/"+uuid.New().String(), "127.0.0.1:41004", testAdminToken, nil)
	if del404.Code != http.StatusNotFound {
		t.Fatalf("expected 404 deleting missing invite, got %d", del404.Code)
	}

	// Settings persistence round-trip via Store.
	reqAuthFalse := false
	if _, err := h.settings.UpdateContext(context.Background(), SettingsPatch{RequireAuth: &reqAuthFalse}); err != nil {
		t.Fatalf("update require_auth=false: %v", err)
	}
	reloaded := NewSettingsStoreWithStore(h.store)
	if err := reloaded.Load(context.Background()); err != nil {
		t.Fatalf("reload settings: %v", err)
	}
	if reloaded.IsRequireAuth() {
		t.Fatal("expected reloaded require_auth=false from app_settings")
	}
}

func TestServiceWorkerDoesNotCacheAuthOrRootPages(t *testing.T) {
	swBytes, err := os.ReadFile(filepath.Join("..", "public", "sw.js"))
	if err != nil {
		t.Fatalf("read public/sw.js: %v", err)
	}
	sw := string(swBytes)
	if !strings.Contains(sw, `audown-shell-v3`) {
		t.Fatal("public/sw.js must bump CACHE_NAME to audown-shell-v3")
	}
	if strings.Contains(sw, `"/"`) {
		t.Fatal("public/sw.js must NOT cache '/'")
	}
	if !strings.Contains(sw, `pathname.startsWith("/static/")`) {
		t.Fatal("public/sw.js must restrict caching to /static/*, /manifest.webmanifest, /favicon.ico")
	}
}

func TestSecurityReviewRegressions(t *testing.T) {
	h := newAuthTestHarness(t, "https://audown.cubus.sh")

	// 1. Static directory listings must return 404.
	for _, dirPath := range []string{"/static/", "/static/js/"} {
		rec := httptest.NewRecorder()
		h.pubH.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, dirPath, nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404 for directory listing %s, got %d", dirPath, rec.Code)
		}
	}

	// 2. Uncleaned invite URL paths must still be redacted in logs.
	for _, rawPath := range []string{
		"/invite/secret-token-123",
		"//invite/secret-token-123",
		"/./invite/secret-token-123",
		"/foo/../invite/secret-token-123",
		"/INVITE/secret-token-123",
	} {
		if got := sanitizePathForLog(rawPath); got != "/invite/[redacted]" {
			t.Fatalf("sanitizePathForLog(%q) = %q, want /invite/[redacted]", rawPath, got)
		}
	}

	// 3. clientIPKey only trusts X-Real-IP from loopback/private proxy peers, never public peers.
	pubPeerReq := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/begin", nil)
	pubPeerReq.RemoteAddr = "203.0.113.50:4444"
	pubPeerReq.Header.Set("X-Real-IP", "198.51.100.99")
	if got := clientIPKey(pubPeerReq); got != "203.0.113.50" {
		t.Fatalf("public peer must not trust X-Real-IP: got %q", got)
	}
	proxyPeerReq := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/begin", nil)
	proxyPeerReq.RemoteAddr = "172.18.0.2:4444"
	proxyPeerReq.Header.Set("X-Real-IP", "198.51.100.99")
	if got := clientIPKey(proxyPeerReq); got != "198.51.100.99" {
		t.Fatalf("private proxy peer should use X-Real-IP: got %q", got)
	}

	// 4. Rate limiter cap must not wipe existing active entries.
	lim := newIPRateLimiter(time.Minute, 2, 2)
	base := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	if !lim.Allow("ip-old", base) || !lim.Allow("ip-hot", base.Add(time.Second)) || !lim.Allow("ip-hot", base.Add(time.Second)) {
		t.Fatal("initial rate limiter hits unexpectedly denied")
	}
	// ip-hot is now saturated (2/2). Adding ip-new evicts ip-old (earliest reset), NOT ip-hot.
	if !lim.Allow("ip-new", base.Add(2*time.Second)) {
		t.Fatal("expected ip-new allowed after evicting oldest entry")
	}
	if lim.Allow("ip-hot", base.Add(2*time.Second)) {
		t.Fatal("rate limiter cap wiped active saturated ip-hot entry")
	}

	// 5. Concurrent SignCount race: two fresh challenges with same signCount=2 -> strictly 1 succeeds, 1 gets 401.
	_, tok := h.createInvite(t, "Counter Race", 24)
	pk := newVirtualPasskey(t, h.cfg.RPID, h.cfg.RPOrigin)
	_, userID := h.enrollPasskey(t, tok, pk, 1)

	var loginBodies [2][]byte
	for i := range 2 {
		bReq := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/begin", strings.NewReader("{}"))
		bReq.Header.Set("Origin", h.cfg.RPOrigin)
		bRec := httptest.NewRecorder()
		h.pubH.ServeHTTP(bRec, bReq)
		var lb struct {
			ChallengeID string `json:"challenge_id"`
			PublicKey   struct {
				Challenge string `json:"challenge"`
			} `json:"publicKey"`
		}
		_ = json.Unmarshal(bRec.Body.Bytes(), &lb)
		body, _ := json.Marshal(map[string]any{
			"challenge_id": lb.ChallengeID,
			"credential":   pk.makeAssertionPayload(t, lb.PublicKey.Challenge, 2, "", nil),
		})
		loginBodies[i] = body
	}
	var (
		wg  sync.WaitGroup
		okN atomic.Int32
		rej atomic.Int32
	)
	gate := make(chan struct{})
	for i := range 2 {
		wg.Add(1)
		go func(payload []byte) {
			defer wg.Done()
			<-gate
			req := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/finish", bytes.NewReader(payload))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", h.cfg.RPOrigin)
			rec := httptest.NewRecorder()
			h.pubH.ServeHTTP(rec, req)
			if rec.Code == http.StatusOK {
				okN.Add(1)
			} else if rec.Code == http.StatusUnauthorized {
				rej.Add(1)
			}
		}(loginBodies[i])
	}
	close(gate)
	wg.Wait()
	if okN.Load() != 1 || rej.Load() != 1 {
		t.Fatalf("concurrent signCount race expected 1x200 and 1x401, got ok=%d rej=%d", okN.Load(), rej.Load())
	}

	// 6. Disabled-user oracle check: invalid signature for disabled user returns 401 (not 403).
	disRec := doAdminReq(t, h.adminH, http.MethodPatch, "/admin/v1/users/"+userID, "127.0.0.1:41010", testAdminToken, map[string]string{"status": "disabled"})
	if disRec.Code != http.StatusOK {
		t.Fatalf("disable user failed: %d", disRec.Code)
	}
	bReq := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/begin", strings.NewReader("{}"))
	bReq.Header.Set("Origin", h.cfg.RPOrigin)
	bRec := httptest.NewRecorder()
	h.pubH.ServeHTTP(bRec, bReq)
	var lb struct {
		ChallengeID string `json:"challenge_id"`
		PublicKey   struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	_ = json.Unmarshal(bRec.Body.Bytes(), &lb)
	// Forge assertion signed with wrong key (different virtualPasskey) but same credID + userHandle.
	wrongPK := newVirtualPasskey(t, h.cfg.RPID, h.cfg.RPOrigin)
	wrongPK.credID = pk.credID
	wrongPK.userHandle = pk.userHandle
	forgedBody, _ := json.Marshal(map[string]any{
		"challenge_id": lb.ChallengeID,
		"credential":   wrongPK.makeAssertionPayload(t, lb.PublicKey.Challenge, 5, "", nil),
	})
	forgedReq := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/finish", bytes.NewReader(forgedBody))
	forgedReq.Header.Set("Content-Type", "application/json")
	forgedReq.Header.Set("Origin", h.cfg.RPOrigin)
	forgedRec := httptest.NewRecorder()
	h.pubH.ServeHTTP(forgedRec, forgedReq)
	if forgedRec.Code != http.StatusUnauthorized {
		t.Fatalf("forged signature for disabled user must return 401 (no 403 oracle), got %d", forgedRec.Code)
	}

	// 7. auth.js must not use inline .style. mutations (CSP style-src 'self' compliance).
	authJSBytes, err := os.ReadFile(filepath.Join("..", "public", "static", "js", "auth.js"))
	if err != nil {
		t.Fatalf("read public/static/js/auth.js: %v", err)
	}
	if strings.Contains(string(authJSBytes), ".style.") {
		t.Fatal("public/static/js/auth.js must not use inline .style. mutations under CSP style-src 'self'")
	}
}
