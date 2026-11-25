package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const testAdminToken = "audown-super-secret-admin-token-123456"

func mapEnv(vars map[string]string) func(string) string {
	return func(key string) string {
		return vars[key]
	}
}

func assertAdminSecurityHeaders(t *testing.T, h http.Header) {
	t.Helper()
	if got := h.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("expected Cache-Control=no-store, got %q", got)
	}
	if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("expected X-Content-Type-Options=nosniff, got %q", got)
	}
}

func doAdminReq(t *testing.T, h http.Handler, method, path, remoteAddr, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	switch v := body.(type) {
	case nil:
		reader = nil
	case string:
		reader = strings.NewReader(v)
	case []byte:
		reader = bytes.NewReader(v)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, reader)
	req.RemoteAddr = remoteAddr
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertAdminSecurityHeaders(t, rec.Header())
	return rec
}

func TestLoadConfigAdminValidation(t *testing.T) {
	// Disabled by default when ADMIN_API_TOKEN is unset or whitespace-only.
	for _, tok := range []string{"", "   \t  "} {
		cfg, err := LoadConfig(mapEnv(map[string]string{
			"ADMIN_API_TOKEN": tok,
			"YOUTUBE_API_KEY": "yt-secret-value-not-logged",
		}))
		if err != nil {
			t.Fatalf("expected disabled admin config to succeed for %q, got: %v", tok, err)
		}
		if cfg.AdminAPIToken != "" {
			t.Fatalf("expected empty AdminAPIToken, got %q", cfg.AdminAPIToken)
		}
		if cfg.AdminPort != DefaultAdminPort {
			t.Fatalf("expected default AdminPort %d, got %d", DefaultAdminPort, cfg.AdminPort)
		}
		// Empty PUBLIC_DIR_NAME must default to "public", never raw CWD.
		if filepath.Base(cfg.PublicDir) != DefaultPublicDir {
			t.Fatalf("expected default PublicDir basename %q, got %q", DefaultPublicDir, cfg.PublicDir)
		}
	}

	// Secret redaction in String() and LogValue().
	cfg, err := LoadConfig(mapEnv(map[string]string{
		"ADMIN_API_TOKEN": testAdminToken,
		"ADMIN_BIND_CIDR": "172.31.0.0/24",
	}))
	if err != nil {
		t.Fatalf("valid config failed: %v", err)
	}
	if strings.Contains(cfg.String(), testAdminToken) {
		t.Fatal("Config.String leaked ADMIN_API_TOKEN")
	}
	if strings.Contains(cfg.LogValue().String(), testAdminToken) {
		t.Fatal("Config.LogValue leaked ADMIN_API_TOKEN")
	}
	// ADMIN_ALLOW_CIDR defaults to ADMIN_BIND_CIDR when unset.
	if cfg.AdminAllowCIDR == nil || cfg.AdminAllowCIDR.String() != "172.31.0.0/24" {
		t.Fatalf("expected AdminAllowCIDR to default to 172.31.0.0/24, got %v", cfg.AdminAllowCIDR)
	}

	// Explicit ADMIN_ALLOW_CIDR overrides ADMIN_BIND_CIDR default.
	cfg2, err := LoadConfig(mapEnv(map[string]string{
		"ADMIN_API_TOKEN":  testAdminToken,
		"ADMIN_BIND_CIDR":  "172.31.0.0/24",
		"ADMIN_ALLOW_CIDR": "172.31.0.2/32",
		"ADMIN_PORT":       "9099",
	}))
	if err != nil {
		t.Fatalf("valid explicit allow CIDR failed: %v", err)
	}
	if cfg2.AdminAllowCIDR == nil || cfg2.AdminAllowCIDR.String() != "172.31.0.2/32" || cfg2.AdminPort != 9099 {
		t.Fatalf("unexpected config: %+v", cfg2)
	}

	// Loopback ADMIN_ALLOW_CIDR without ADMIN_BIND_CIDR is allowed.
	if _, err := LoadConfig(mapEnv(map[string]string{
		"ADMIN_API_TOKEN":  testAdminToken,
		"ADMIN_ALLOW_CIDR": "127.0.0.1/32",
	})); err != nil {
		t.Fatalf("expected loopback ADMIN_ALLOW_CIDR without ADMIN_BIND_CIDR to succeed, got %v", err)
	}

	badCases := []struct {
		name string
		env  map[string]string
	}{
		{"short token", map[string]string{"ADMIN_API_TOKEN": "too-short-15chr"}},
		{"placeholder lower", map[string]string{"ADMIN_API_TOKEN": "replace-with-a-random-admin-api-token"}},
		{"placeholder upper", map[string]string{"ADMIN_API_TOKEN": "REPLACE-WITH-SOMETHING-SECRET"}},
		{"placeholder changeme", map[string]string{"ADMIN_API_TOKEN": "changeme"}},
		{"token with space", map[string]string{"ADMIN_API_TOKEN": "valid-length-with space-inside"}},
		{"admin port 0", map[string]string{"ADMIN_API_TOKEN": testAdminToken, "ADMIN_PORT": "0"}},
		{"admin port 65536", map[string]string{"ADMIN_API_TOKEN": testAdminToken, "ADMIN_PORT": "65536"}},
		{"admin port non-numeric", map[string]string{"ADMIN_API_TOKEN": testAdminToken, "ADMIN_PORT": "abc"}},
		{"admin port collides with main", map[string]string{"ADMIN_API_TOKEN": testAdminToken, "LISTEN_ADDR": ":80", "ADMIN_PORT": "80"}},
		{"admin port collides default 9090", map[string]string{"ADMIN_API_TOKEN": testAdminToken, "LISTEN_ADDR": ":9090"}},
		{"bind CIDR invalid", map[string]string{"ADMIN_API_TOKEN": testAdminToken, "ADMIN_BIND_CIDR": "not-a-cidr"}},
		{"bind CIDR /0", map[string]string{"ADMIN_API_TOKEN": testAdminToken, "ADMIN_BIND_CIDR": "0.0.0.0/0"}},
		{"bind CIDR ::/0", map[string]string{"ADMIN_API_TOKEN": testAdminToken, "ADMIN_BIND_CIDR": "::/0"}},
		{"allow CIDR /0", map[string]string{"ADMIN_API_TOKEN": testAdminToken, "ADMIN_ALLOW_CIDR": "0.0.0.0/0"}},
		{"allow CIDR 4in6", map[string]string{"ADMIN_API_TOKEN": testAdminToken, "ADMIN_ALLOW_CIDR": "::ffff:172.31.0.0/120"}},
		{"non-loopback allow CIDR without bind CIDR", map[string]string{"ADMIN_API_TOKEN": testAdminToken, "ADMIN_ALLOW_CIDR": "172.31.0.2/32"}},
	}
	for _, tc := range badCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := LoadConfig(mapEnv(tc.env)); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}

	// ValidatePublicDir rejects missing path and files, accepts directories.
	if err := ValidatePublicDir(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected ValidatePublicDir to fail on missing dir")
	}
	fPath := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(fPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePublicDir(fPath); err == nil {
		t.Fatal("expected ValidatePublicDir to fail on regular file")
	}
	if err := ValidatePublicDir(t.TempDir()); err != nil {
		t.Fatalf("expected ValidatePublicDir to succeed on directory: %v", err)
	}
}

func TestResolveBindAddr(t *testing.T) {
	addr, err := ResolveBindAddr(nil, 9090)
	if err != nil {
		t.Fatalf("ResolveBindAddr(nil) failed: %v", err)
	}
	if addr != "127.0.0.1:9090" {
		t.Fatalf("expected 127.0.0.1:9090, got %q", addr)
	}

	pfx := netip.MustParsePrefix("172.31.0.0/24")
	addrs := []net.Addr{
		&net.IPNet{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(0, 32)},
		&net.IPNet{IP: net.IPv4(127, 0, 0, 1), Mask: net.CIDRMask(8, 32)},
		&net.IPNet{IP: net.IPv4(172, 20, 0, 10), Mask: net.CIDRMask(16, 32)},
		&net.IPNet{IP: net.IPv4(172, 31, 0, 130), Mask: net.CIDRMask(24, 32)},
	}
	resolved, err := resolveBindAddrFrom(addrs, &pfx, 9090)
	if err != nil {
		t.Fatalf("resolveBindAddrFrom failed: %v", err)
	}
	if resolved != "172.31.0.130:9090" {
		t.Fatalf("expected 172.31.0.130:9090, got %q", resolved)
	}

	noMatchAddrs := []net.Addr{
		&net.IPNet{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(0, 32)},
		&net.IPNet{IP: net.IPv4(127, 0, 0, 1), Mask: net.CIDRMask(8, 32)},
		&net.IPNet{IP: net.IPv4(172, 20, 0, 10), Mask: net.CIDRMask(16, 32)},
	}
	if _, err := resolveBindAddrFrom(noMatchAddrs, &pfx, 9090); err == nil {
		t.Fatal("expected error when no local interface matches ADMIN_BIND_CIDR")
	}

	loPfx := netip.MustParsePrefix("127.0.0.0/8")
	loAddr, err := ResolveBindAddr(&loPfx, 9095)
	if err != nil {
		t.Fatalf("expected loopback interface resolution to succeed, got %v", err)
	}
	if !strings.HasPrefix(loAddr, "127.") || !strings.HasSuffix(loAddr, ":9095") {
		t.Fatalf("unexpected loopback bind addr %q", loAddr)
	}

	missingPfx := netip.MustParsePrefix("198.51.100.0/24")
	if _, err := ResolveBindAddr(&missingPfx, 9090); err == nil {
		t.Fatal("expected ResolveBindAddr to fail for unconfigured TEST-NET-2 CIDR")
	}
}

func TestNewAdminServerValidation(t *testing.T) {
	st := NewSettingsStore()
	if _, err := NewAdminServer(nil, testAdminToken, nil); err == nil {
		t.Fatal("expected NewAdminServer to reject nil settings")
	}
	if _, err := NewAdminServer(st, "", nil); err == nil {
		t.Fatal("expected NewAdminServer to reject empty token")
	}
	if _, err := NewAdminServer(st, "short", nil); err == nil {
		t.Fatal("expected NewAdminServer to reject short token")
	}
	if _, err := NewAdminServer(st, "replace-with-random-token-value", nil); err == nil {
		t.Fatal("expected NewAdminServer to reject placeholder token")
	}
	slashZero := netip.MustParsePrefix("0.0.0.0/0")
	if _, err := NewAdminServer(st, testAdminToken, &slashZero); err == nil {
		t.Fatal("expected NewAdminServer to reject /0 allowCIDR")
	}
	v4in6 := netip.MustParsePrefix("::ffff:172.31.0.0/120")
	if _, err := NewAdminServer(st, testAdminToken, &v4in6); err == nil {
		t.Fatal("expected NewAdminServer to reject IPv4-mapped IPv6 allowCIDR")
	}
}

func TestAdminAPICIDRAuthAndMethodErrors(t *testing.T) {
	st := NewSettingsStore()
	allow := netip.MustParsePrefix("172.31.0.2/32")
	srv, err := NewAdminServer(st, testAdminToken, &allow)
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	// Sibling container IP on same /24 -> 403 even with valid token and spoofed XFF.
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/manifest", nil)
	req.RemoteAddr = "172.31.0.130:44444"
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	req.Header.Set("X-Forwarded-For", "172.31.0.2, 127.0.0.1")
	req.Header.Set("X-Real-IP", "172.31.0.2")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertAdminSecurityHeaders(t, rec.Header())
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for sibling IP with spoofed XFF, got %d", rec.Code)
	}

	// Malformed RemoteAddr -> 403.
	rec = doAdminReq(t, h, http.MethodGet, "/admin/v1/manifest", "not-an-ip", testAdminToken, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for invalid RemoteAddr, got %d", rec.Code)
	}

	// Allowed peer with missing/bad/wrong-scheme Authorization -> 401 + WWW-Authenticate.
	for _, authVal := range []string{"", "Basic dXNlcjpwYXNz", "Bearer", "Bearer wrong-token", "Token " + testAdminToken} {
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/manifest", nil)
		req.RemoteAddr = "172.31.0.2:55555"
		if authVal != "" {
			req.Header.Set("Authorization", authVal)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assertAdminSecurityHeaders(t, rec.Header())
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for auth %q, got %d", authVal, rec.Code)
		}
		if got := rec.Header().Get("WWW-Authenticate"); got != `Bearer realm="audown-admin"` {
			t.Fatalf("expected WWW-Authenticate header, got %q", got)
		}
	}

	// Multiple Authorization headers -> 401.
	req = httptest.NewRequest(http.MethodGet, "/admin/v1/manifest", nil)
	req.RemoteAddr = "172.31.0.2:55555"
	req.Header.Add("Authorization", "Bearer "+testAdminToken)
	req.Header.Add("Authorization", "Bearer "+testAdminToken)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertAdminSecurityHeaders(t, rec.Header())
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for duplicate Authorization headers, got %d", rec.Code)
	}

	// Allowed peer (including IPv4-mapped IPv6) + valid Bearer token -> 200.
	rec = doAdminReq(t, h, http.MethodGet, "/admin/v1/manifest", "[::ffff:172.31.0.2]:55555", testAdminToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for allowed peer, got %d: %s", rec.Code, rec.Body.String())
	}

	// Unsupported HTTP methods return JSON 405 (never plain text).
	for _, tc := range []struct {
		method string
		path   string
		allow  string
	}{
		{http.MethodPost, "/admin/v1/manifest", "GET"},
		{http.MethodPost, "/admin/v1/settings", "GET, PATCH"},
		{http.MethodDelete, "/admin/v1/settings", "GET, PATCH"},
	} {
		rec = doAdminReq(t, h, tc.method, tc.path, "172.31.0.2:55555", testAdminToken, nil)
		if rec.Code != http.StatusMethodNotAllowed || !json.Valid(rec.Body.Bytes()) {
			t.Fatalf("expected JSON 405 for %s %s, got %d %q", tc.method, tc.path, rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Allow"); got != tc.allow {
			t.Fatalf("expected Allow=%q, got %q", tc.allow, got)
		}
	}

	// Loopback-only mode when allowCIDR == nil.
	loSrv, err := NewAdminServer(st, testAdminToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	loH := loSrv.Handler()

	req = httptest.NewRequest(http.MethodGet, "/admin/v1/settings", nil)
	req.RemoteAddr = "10.0.0.5:12345"
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	rec = httptest.NewRecorder()
	loH.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-loopback even with XFF=127.0.0.1, got %d", rec.Code)
	}

	rec = doAdminReq(t, loH, http.MethodGet, "/admin/v1/settings", "[::1]:12345", testAdminToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for IPv6 loopback, got %d", rec.Code)
	}

	// Unknown route -> JSON 404 with security headers.
	rec = doAdminReq(t, loH, http.MethodGet, "/admin/v1/unknown", "127.0.0.1:12345", testAdminToken, nil)
	if rec.Code != http.StatusNotFound || !json.Valid(rec.Body.Bytes()) {
		t.Fatalf("expected JSON 404, got %d %q", rec.Code, rec.Body.String())
	}
}

func TestAdminAPIManifestAndSettingsContract(t *testing.T) {
	t.Setenv("YOUTUBE_API_KEY", "AIzaSySecretYoutubeKeyMustNeverLeak")

	st := NewSettingsStore()
	srv, err := NewAdminServer(st, testAdminToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	manRec := doAdminReq(t, h, http.MethodGet, "/admin/v1/manifest", "127.0.0.1:40001", testAdminToken, nil)
	if manRec.Code != http.StatusOK {
		t.Fatalf("manifest status %d: %s", manRec.Code, manRec.Body.String())
	}
	if strings.Contains(manRec.Body.String(), "AIzaSySecretYoutubeKeyMustNeverLeak") ||
		strings.Contains(manRec.Body.String(), testAdminToken) {
		t.Fatal("manifest leaked secret env value")
	}

	var manifest struct {
		Service        string            `json:"service"`
		Version        string            `json:"version"`
		Capabilities   []string          `json:"capabilities"`
		Endpoints      map[string]string `json:"endpoints"`
		SettingsSchema []struct {
			Key   string `json:"key"`
			Label string `json:"label"`
			Type  string `json:"type"`
			Min   *int   `json:"min"`
			Max   *int   `json:"max"`
			Help  string `json:"help"`
		} `json:"settings_schema"`
	}
	if err := json.Unmarshal(manRec.Body.Bytes(), &manifest); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	if manifest.Service != "audown" || manifest.Version == "" {
		t.Fatalf("unexpected manifest service/version: %+v", manifest)
	}
	if len(manifest.Capabilities) != 1 || manifest.Capabilities[0] != "settings" {
		t.Fatalf("unexpected capabilities: %v", manifest.Capabilities)
	}
	if manifest.Endpoints["settings_get"] != "GET /admin/v1/settings" ||
		manifest.Endpoints["settings_update"] != "PATCH /admin/v1/settings" {
		t.Fatalf("unexpected endpoints: %v", manifest.Endpoints)
	}
	if len(manifest.SettingsSchema) != 4 {
		t.Fatalf("expected 4 schema entries, got %d", len(manifest.SettingsSchema))
	}

	getRec := doAdminReq(t, h, http.MethodGet, "/admin/v1/settings", "127.0.0.1:40001", testAdminToken, nil)
	if getRec.Code != http.StatusOK {
		t.Fatalf("get settings status %d: %s", getRec.Code, getRec.Body.String())
	}
	if strings.Contains(getRec.Body.String(), "AIzaSySecretYoutubeKeyMustNeverLeak") ||
		strings.Contains(getRec.Body.String(), testAdminToken) {
		t.Fatal("settings leaked secret env value")
	}
	var current map[string]any
	if err := json.Unmarshal(getRec.Body.Bytes(), &current); err != nil {
		t.Fatalf("unmarshal settings: %v", err)
	}
	for _, field := range manifest.SettingsSchema {
		if _, ok := current[field.Key]; !ok {
			t.Fatalf("schema key %q missing from GET /admin/v1/settings", field.Key)
		}
		switch field.Type {
		case "bool", "int", "float", "string", "string_list":
		default:
			t.Fatalf("unsupported admin.cubus.sh schema type %q", field.Type)
		}
	}
}

func TestAdminAPIPatchValidationAndPartialUpdates(t *testing.T) {
	st := NewSettingsStore()
	srv, err := NewAdminServer(st, testAdminToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	// Oversized (> 16 KiB) body -> 413.
	huge := fmt.Sprintf(`{"audio_format":%q}`, strings.Repeat("a", maxAdminBodyBytes+128))
	rec := doAdminReq(t, h, http.MethodPatch, "/admin/v1/settings", "127.0.0.1:40002", testAdminToken, huge)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for oversized PATCH body, got %d: %s", rec.Code, rec.Body.String())
	}

	invalidPayloads := []struct {
		name string
		body string
	}{
		{"empty body", ""},
		{"top-level null", "null"},
		{"top-level array", "[]"},
		{"invalid JSON", `{"accept_downloads":`},
		{"unknown field", `{"unknown_knob": true}`},
		{"trailing JSON object", `{"accept_downloads": false}{"accept_downloads": true}`},
		{"trailing junk", `{"accept_downloads": false} trailing`},
		{"wrong bool type", `{"accept_downloads": "false"}`},
		{"wrong int type float", `{"ytdlp_timeout_seconds": 15.5}`},
		{"wrong int type string", `{"ytdlp_timeout_seconds": "120"}`},
		{"explicit null field", `{"accept_downloads": null}`},
		{"timeout below min", `{"ytdlp_timeout_seconds": 9}`},
		{"timeout above max", `{"ytdlp_timeout_seconds": 601}`},
		{"concurrency below min", `{"max_concurrent_downloads": 0}`},
		{"concurrency above max", `{"max_concurrent_downloads": 33}`},
		{"unsupported audio format", `{"audio_format": "ogg"}`},
		{"flag injection in audio format", `{"audio_format": "mp3 --exec touch"}`},
		{"atomic rejection with mixed valid+invalid", `{"accept_downloads": false, "ytdlp_timeout_seconds": 9999}`},
	}
	for _, tc := range invalidPayloads {
		t.Run(tc.name, func(t *testing.T) {
			rec := doAdminReq(t, h, http.MethodPatch, "/admin/v1/settings", "127.0.0.1:40002", testAdminToken, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for %s, got %d: %s", tc.name, rec.Code, rec.Body.String())
			}
		})
	}

	if got := st.Get(); got != DefaultSettings() {
		t.Fatalf("invalid PATCH mutated settings: %+v", got)
	}

	// Empty object {} is a valid no-op returning current settings.
	rec = doAdminReq(t, h, http.MethodPatch, "/admin/v1/settings", "127.0.0.1:40002", testAdminToken, "{}")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for empty object PATCH, got %d", rec.Code)
	}

	// Single-field partial update preserves all other fields.
	rec = doAdminReq(t, h, http.MethodPatch, "/admin/v1/settings", "127.0.0.1:40002", testAdminToken, `{"ytdlp_timeout_seconds":75}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for 1-field partial PATCH, got %d: %s", rec.Code, rec.Body.String())
	}
	var partial RuntimeSettings
	if err := json.Unmarshal(rec.Body.Bytes(), &partial); err != nil {
		t.Fatal(err)
	}
	if !partial.AcceptDownloads || partial.YtDlpTimeoutSeconds != 75 ||
		partial.MaxConcurrentDownloads != defaultMaxConcurrentDownloads || partial.AudioFormat != defaultAudioFormat {
		t.Fatalf("1-field PATCH did not preserve siblings: %+v", partial)
	}

	// Full update normalizes audio_format and updates all fields.
	rec = doAdminReq(t, h, http.MethodPatch, "/admin/v1/settings", "127.0.0.1:40002", testAdminToken, map[string]any{
		"accept_downloads":         false,
		"ytdlp_timeout_seconds":    45,
		"max_concurrent_downloads": 2,
		"audio_format":             "  M4A ",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid PATCH, got %d: %s", rec.Code, rec.Body.String())
	}
	var updated RuntimeSettings
	if err := json.Unmarshal(rec.Body.Bytes(), &updated); err != nil {
		t.Fatalf("unmarshal updated settings: %v", err)
	}
	if updated.AcceptDownloads || updated.YtDlpTimeoutSeconds != 45 ||
		updated.MaxConcurrentDownloads != 2 || updated.AudioFormat != "m4a" {
		t.Fatalf("unexpected updated settings: %+v", updated)
	}
}

func TestDownloadValidationErrorPathsAndFormats(t *testing.T) {
	pubDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(pubDir, "index.html"), []byte("<html>ok</html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pubDir, ".env"), []byte("SECRET=1"), 0o600); err != nil {
		t.Fatal(err)
	}

	st := NewSettingsStore()
	adminSrv, err := NewAdminServer(st, testAdminToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	adminH := adminSrv.Handler()

	mode := "ok"
	app := newAppServer(pubDir, st, func(ctx context.Context, outputPattern, audioFormat, _, _, _ string) error {
		dir := filepath.Dir(outputPattern)
		switch mode {
		case "timeout":
			<-ctx.Done()
			return ctx.Err()
		case "fail":
			return errors.New("yt-dlp failed")
		case "zero_files":
			return nil
		case "two_files":
			_ = os.WriteFile(filepath.Join(dir, "a."+audioFormat), []byte("1"), 0o600)
			_ = os.WriteFile(filepath.Join(dir, "b."+audioFormat), []byte("2"), 0o600)
			return nil
		case "dir_output":
			return os.Mkdir(filepath.Join(dir, "subdir"), 0o700)
		case "symlink_output":
			return os.Symlink("/etc/passwd", filepath.Join(dir, "evil."+audioFormat))
		default:
			return os.WriteFile(filepath.Join(dir, "sample."+audioFormat), []byte("audio-bytes"), 0o600)
		}
	})
	pubH := app.handler()

	// Dotfile access under publicDir must return 404.
	dotReq := httptest.NewRequest(http.MethodGet, "/.env", nil)
	dotRec := httptest.NewRecorder()
	pubH.ServeHTTP(dotRec, dotReq)
	if dotRec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for /.env, got %d", dotRec.Code)
	}

	// Method checks on public routes.
	getDl := httptest.NewRequest(http.MethodGet, "/download", nil)
	getDlRec := httptest.NewRecorder()
	pubH.ServeHTTP(getDlRec, getDl)
	if getDlRec.Code != http.StatusMethodNotAllowed || getDlRec.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("expected 405 Allow: POST for GET /download, got %d Allow=%q", getDlRec.Code, getDlRec.Header().Get("Allow"))
	}

	postRoot := httptest.NewRequest(http.MethodPost, "/", nil)
	postRootRec := httptest.NewRecorder()
	pubH.ServeHTTP(postRootRec, postRoot)
	if postRootRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for POST /, got %d", postRootRec.Code)
	}

	// URL and time validation cases -> 303 redirect to badReqURL.
	badForms := []struct {
		name string
		form url.Values
	}{
		{"empty url", url.Values{}},
		{"non-youtube url", url.Values{"url": {"https://evil.example/watch?v=dQw4w9WgXcQ"}}},
		{"playlist url rejected", url.Values{"url": {"https://www.youtube.com/playlist?list=PL123"}}},
		{"url with space", url.Values{"url": {"https://www.youtube.com/watch?v=dQw4w9WgXcQ extra"}}},
		{"url with port", url.Values{"url": {"https://www.youtube.com:443/watch?v=dQw4w9WgXcQ"}}},
		{"bad startTime format", url.Values{"url": {"https://www.youtube.com/watch?v=dQw4w9WgXcQ"}, "startTime": {"bad"}}},
		{"bad endTime format", url.Values{"url": {"https://www.youtube.com/watch?v=dQw4w9WgXcQ"}, "endTime": {"00:99:00"}}},
		{"startTime >= endTime", url.Values{"url": {"https://www.youtube.com/watch?v=dQw4w9WgXcQ"}, "startTime": {"00:01:00"}, "endTime": {"00:00:30"}}},
	}
	for _, tc := range badForms {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/download", strings.NewReader(tc.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			pubH.ServeHTTP(rec, req)
			if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != app.badReqURL {
				t.Fatalf("expected 303 to badReqURL, got %d location=%q", rec.Code, rec.Header().Get("Location"))
			}
		})
	}

	// Oversized form body > 16 KiB -> 303 badReqURL.
	bigForm := url.Values{"url": {"https://www.youtube.com/watch?v=dQw4w9WgXcQ"}, "pad": {strings.Repeat("x", maxDownloadFormBytes+100)}}
	bigReq := httptest.NewRequest(http.MethodPost, "/download", strings.NewReader(bigForm.Encode()))
	bigReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	bigRec := httptest.NewRecorder()
	pubH.ServeHTTP(bigRec, bigReq)
	if bigRec.Code != http.StatusSeeOther || bigRec.Header().Get("Location") != app.badReqURL {
		t.Fatalf("expected 303 badReqURL for oversized form, got %d location=%q", bigRec.Code, bigRec.Header().Get("Location"))
	}

	// Runner failure modes -> proper redirect and slot release.
	for _, tc := range []struct {
		mode     string
		expected string
	}{
		{"fail", app.internalURL},
		{"zero_files", app.internalURL},
		{"two_files", app.internalURL},
		{"dir_output", app.internalURL},
		{"symlink_output", app.internalURL},
	} {
		mode = tc.mode
		form := url.Values{"url": {"https://www.youtube.com/shorts/dQw4w9WgXcQ"}}
		req := httptest.NewRequest(http.MethodPost, "/download", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		pubH.ServeHTTP(rec, req)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != tc.expected {
			t.Fatalf("mode %s: expected 303 %q, got %d %q", tc.mode, tc.expected, rec.Code, rec.Header().Get("Location"))
		}
		if st.ActiveDownloads() != 0 {
			t.Fatalf("mode %s leaked download slot: active=%d", tc.mode, st.ActiveDownloads())
		}
	}

	// Timeout mode -> timeoutURL redirect (simulated cleanly via pre-expired context or short Wait).
	mode = "timeout"
	req := httptest.NewRequest(http.MethodPost, "/download", strings.NewReader(url.Values{"url": {"https://youtu.be/dQw4w9WgXcQ"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx, cancel := context.WithDeadline(req.Context(), time.Now().Add(-time.Second))
	defer cancel()
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	pubH.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != app.timeoutURL {
		t.Fatalf("expected 303 timeoutURL on deadline exceeded, got %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if st.ActiveDownloads() != 0 {
		t.Fatalf("timeout leaked download slot: active=%d", st.ActiveDownloads())
	}

	// All AllowedAudioFormats emit expected Content-Type, Content-Disposition, security headers, and valid cookie only when token matches pattern.
	mode = "ok"
	expectedMIME := map[string]string{
		"mp3":  "audio/mpeg",
		"m4a":  "audio/mp4",
		"opus": "audio/opus",
		"flac": "audio/flac",
		"wav":  "audio/wav",
	}
	for _, format := range AllowedAudioFormats {
		patchRec := doAdminReq(t, adminH, http.MethodPatch, "/admin/v1/settings", "127.0.0.1:40010", testAdminToken, map[string]any{"audio_format": format})
		if patchRec.Code != http.StatusOK {
			t.Fatalf("patch format %s failed: %d", format, patchRec.Code)
		}

		// Valid downloadToken -> cookie set.
		validTok := "abcdef0123456789abcdef"
		form := url.Values{"url": {"https://www.youtube.com/watch?v=dQw4w9WgXcQ"}, "downloadToken": {validTok}}
		req := httptest.NewRequest(http.MethodPost, "/download", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		pubH.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("format %s: expected 200, got %d", format, rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); got != expectedMIME[format] {
			t.Fatalf("format %s: expected Content-Type %q, got %q", format, expectedMIME[format], got)
		}
		if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "sample."+format) {
			t.Fatalf("format %s: unexpected Content-Disposition %q", format, cd)
		}
		assertAdminSecurityHeaders(t, rec.Header())
		if len(rec.Result().Cookies()) != 1 || rec.Result().Cookies()[0].Value != validTok {
			t.Fatalf("format %s: expected download cookie %q, got %+v", format, validTok, rec.Result().Cookies())
		}

		// Invalid downloadToken -> cookie NOT set.
		form.Set("downloadToken", "bad;cookie=inject")
		req2 := httptest.NewRequest(http.MethodPost, "/download", strings.NewReader(form.Encode()))
		req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec2 := httptest.NewRecorder()
		pubH.ServeHTTP(rec2, req2)
		if len(rec2.Result().Cookies()) != 0 {
			t.Fatalf("expected invalid downloadToken not to emit cookie, got %+v", rec2.Result().Cookies())
		}
	}
}

func TestSanitizedCommandEnvAndSubprocessHelpers(t *testing.T) {
	t.Setenv("ADMIN_API_TOKEN", testAdminToken)
	t.Setenv("YOUTUBE_API_KEY", "AIzaSyShouldNeverReachSubprocess")
	t.Setenv("PATH", "/usr/local/bin:/usr/bin")

	env := sanitizedCommandEnv(os.Getenv)
	for _, entry := range env {
		if strings.HasPrefix(entry, "ADMIN_API_TOKEN=") || strings.HasPrefix(entry, "YOUTUBE_API_KEY=") {
			t.Fatalf("secret env var leaked into sanitizedCommandEnv: %s", entry)
		}
	}
	if !slices.Contains(env, "PATH=/usr/local/bin:/usr/bin") {
		t.Fatalf("expected PATH in sanitizedCommandEnv, got %v", env)
	}
	if !slices.Contains(env, "HOME=/tmp") || !slices.Contains(env, "XDG_CACHE_HOME=/tmp") {
		t.Fatalf("expected HOME/XDG_CACHE_HOME=/tmp in sanitizedCommandEnv, got %v", env)
	}

	args := buildYtDlpArgs("/tmp/dl/%(title)s.%(ext)s", "m4a", "00:00:10", "00:00:20", "https://www.youtube.com/watch?v=dQw4w9WgXcQ")
	if !slices.Contains(args, "--no-cache-dir") || !slices.Contains(args, "--audio-format=m4a") {
		t.Fatalf("unexpected yt-dlp args: %v", args)
	}
	if slices.Contains(args, "-v") {
		t.Fatalf("did not expect verbose -v flag in yt-dlp args: %v", args)
	}
	if len(args) < 2 || args[len(args)-2] != "--" {
		t.Fatalf("expected '--' end-of-options before video URL: %v", args)
	}

	// Verify limitedBuffer caps stderr size.
	lb := &limitedBuffer{limit: 16}
	_, _ = lb.Write([]byte("0123456789"))
	_, _ = lb.Write([]byte("ABCDEFGHIJKLMN"))
	if !strings.HasPrefix(lb.String(), "0123456789ABCDEF") || !strings.Contains(lb.String(), "truncated") {
		t.Fatalf("unexpected limitedBuffer output: %q", lb.String())
	}

	// Verify killProcessGroup terminates a spawned process group cleanly.
	cmd := exec.Command("sleep", "30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := killProcessGroup(cmd); err != nil {
		t.Fatalf("killProcessGroup failed: %v", err)
	}
	_ = cmd.Wait()
}

func TestLiveBehaviorAffectedByAdminSettings(t *testing.T) {
	pubDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(pubDir, "index.html"), []byte("<html>ok</html>"), 0o600); err != nil {
		t.Fatal(err)
	}

	st := NewSettingsStore()
	adminSrv, err := NewAdminServer(st, testAdminToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	adminH := adminSrv.Handler()

	var mu sync.Mutex
	var lastTimeout time.Duration
	var lastAudioFormat string

	app := newAppServer(pubDir, st, func(ctx context.Context, outputPattern, audioFormat, _, _, _ string) error {
		deadline, ok := ctx.Deadline()
		if !ok {
			return fmt.Errorf("missing context deadline")
		}
		mu.Lock()
		lastTimeout = time.Until(deadline)
		lastAudioFormat = audioFormat
		mu.Unlock()

		dir := filepath.Dir(outputPattern)
		return os.WriteFile(filepath.Join(dir, "sample."+audioFormat), []byte("audio-bytes"), 0o600)
	})
	pubH := app.handler()

	postDownload := func(rawURL string) *httptest.ResponseRecorder {
		form := url.Values{"url": {rawURL}}
		req := httptest.NewRequest(http.MethodPost, "/download", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		pubH.ServeHTTP(rec, req)
		return rec
	}

	// 1. Default download succeeds with mp3 + ~110s timeout.
	rec := postDownload("https://www.youtube.com/watch?v=dQw4w9WgXcQ")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected initial download 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "audio/mpeg" {
		t.Fatalf("expected Content-Type audio/mpeg, got %q", ct)
	}
	mu.Lock()
	if lastAudioFormat != "mp3" || lastTimeout < 105*time.Second || lastTimeout > 111*time.Second {
		mu.Unlock()
		t.Fatalf("unexpected initial runner params: format=%q timeout=%v", lastAudioFormat, lastTimeout)
	}
	mu.Unlock()

	// 2. Patch timeout + audio format -> live download reflects both immediately.
	patchRec := doAdminReq(t, adminH, http.MethodPatch, "/admin/v1/settings", "127.0.0.1:40003", testAdminToken, map[string]any{
		"ytdlp_timeout_seconds": 25,
		"audio_format":          "opus",
	})
	if patchRec.Code != http.StatusOK {
		t.Fatalf("patch failed: %d %s", patchRec.Code, patchRec.Body.String())
	}

	rec = postDownload("https://youtu.be/dQw4w9WgXcQ")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected opus download 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "audio/opus" {
		t.Fatalf("expected Content-Type audio/opus, got %q", ct)
	}
	mu.Lock()
	if lastAudioFormat != "opus" || lastTimeout < 20*time.Second || lastTimeout > 26*time.Second {
		mu.Unlock()
		t.Fatalf("unexpected updated runner params: format=%q timeout=%v", lastAudioFormat, lastTimeout)
	}
	mu.Unlock()

	// 3. Maintenance mode (accept_downloads=false) returns 503 on POST /download while GET / stays 200.
	patchRec = doAdminReq(t, adminH, http.MethodPatch, "/admin/v1/settings", "127.0.0.1:40003", testAdminToken, map[string]any{
		"accept_downloads": false,
	})
	if patchRec.Code != http.StatusOK {
		t.Fatalf("pause patch failed: %d", patchRec.Code)
	}

	dlPaused := postDownload("https://www.youtube.com/watch?v=dQw4w9WgXcQ")
	if dlPaused.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when downloads paused, got %d", dlPaused.Code)
	}
	assertAdminSecurityHeaders(t, dlPaused.Header())

	healthReq := httptest.NewRequest(http.MethodGet, "/", nil)
	healthRec := httptest.NewRecorder()
	pubH.ServeHTTP(healthRec, healthReq)
	if healthRec.Code != http.StatusOK {
		t.Fatalf("expected GET / healthcheck 200 during maintenance, got %d", healthRec.Code)
	}

	// Re-enable downloads -> POST /download works again.
	patchRec = doAdminReq(t, adminH, http.MethodPatch, "/admin/v1/settings", "127.0.0.1:40003", testAdminToken, map[string]any{
		"accept_downloads": true,
	})
	if patchRec.Code != http.StatusOK {
		t.Fatalf("resume patch failed: %d", patchRec.Code)
	}
	if dlResumed := postDownload("https://www.youtube.com/watch?v=dQw4w9WgXcQ"); dlResumed.Code != http.StatusOK {
		t.Fatalf("expected 200 after resume, got %d", dlResumed.Code)
	}
}

func TestMaxConcurrentDownloadsDynamicResizeNoDeadlock(t *testing.T) {
	pubDir := t.TempDir()
	st := NewSettingsStore()
	adminSrv, err := NewAdminServer(st, testAdminToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	adminH := adminSrv.Handler()

	patchRec := doAdminReq(t, adminH, http.MethodPatch, "/admin/v1/settings", "127.0.0.1:40004", testAdminToken, map[string]any{
		"max_concurrent_downloads": 1,
	})
	if patchRec.Code != http.StatusOK {
		t.Fatalf("patch failed: %d", patchRec.Code)
	}

	started := make(chan struct{}, 8)
	release := make(chan struct{})

	app := newAppServer(pubDir, st, func(ctx context.Context, outputPattern, audioFormat, _, _, _ string) error {
		started <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
		return os.WriteFile(filepath.Join(filepath.Dir(outputPattern), "ok."+audioFormat), []byte("x"), 0o600)
	})
	pubH := app.handler()

	startAsyncDownload := func() <-chan int {
		ch := make(chan int, 1)
		go func() {
			form := url.Values{"url": {"https://www.youtube.com/watch?v=dQw4w9WgXcQ"}}
			req := httptest.NewRequest(http.MethodPost, "/download", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			pubH.ServeHTTP(rec, req)
			ch <- rec.Code
		}()
		return ch
	}

	j1 := startAsyncDownload()
	<-started

	j2 := startAsyncDownload()
	if code := <-j2; code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 when max_concurrent_downloads=1 saturated, got %d", code)
	}

	// Resize up to 3 while job 1 is in-flight -> jobs 3 and 4 can enter, job 5 gets 429.
	patchRec = doAdminReq(t, adminH, http.MethodPatch, "/admin/v1/settings", "127.0.0.1:40004", testAdminToken, map[string]any{
		"max_concurrent_downloads": 3,
	})
	if patchRec.Code != http.StatusOK {
		t.Fatalf("resize up failed: %d", patchRec.Code)
	}

	j3 := startAsyncDownload()
	<-started
	j4 := startAsyncDownload()
	<-started
	j5 := startAsyncDownload()
	if code := <-j5; code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 when max_concurrent_downloads=3 saturated, got %d", code)
	}

	// Resize down to 1 while 3 jobs are active -> must NOT deadlock; job 6 gets 429.
	patchRec = doAdminReq(t, adminH, http.MethodPatch, "/admin/v1/settings", "127.0.0.1:40004", testAdminToken, map[string]any{
		"max_concurrent_downloads": 1,
	})
	if patchRec.Code != http.StatusOK {
		t.Fatalf("resize down failed: %d", patchRec.Code)
	}
	j6 := startAsyncDownload()
	if code := <-j6; code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 while 3 active > new limit 1, got %d", code)
	}

	close(release)
	for i, ch := range []<-chan int{j1, j3, j4} {
		if code := <-ch; code != http.StatusOK {
			t.Fatalf("active job %d returned %d, expected 200", i, code)
		}
	}
	if active := st.ActiveDownloads(); active != 0 {
		t.Fatalf("expected 0 active downloads after completion, got %d", active)
	}
}

func TestAdminAPIConcurrentRaceAndRealTCP(t *testing.T) {
	pubDir := t.TempDir()
	st := NewSettingsStore()
	adminSrv, err := NewAdminServer(st, testAdminToken, nil)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: adminSrv.Handler()}
	defer srv.Close()
	go func() {
		_ = srv.Serve(ln)
	}()

	// Real TCP public listener with ReadTimeout=30s and deadlineResponseWriter.
	app := newAppServer(pubDir, st, func(_ context.Context, outputPattern, audioFormat, _, _, _ string) error {
		return os.WriteFile(filepath.Join(filepath.Dir(outputPattern), "race."+audioFormat), []byte("ok"), 0o600)
	})
	pubLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pubSrv := &http.Server{
		Handler:           app.handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	defer pubSrv.Close()
	go func() {
		_ = pubSrv.Serve(pubLn)
	}()

	adminBaseURL := "http://" + ln.Addr().String()
	pubBaseURL := "http://" + pubLn.Addr().String()
	client := &http.Client{Timeout: 5 * time.Second}

	var wg sync.WaitGroup
	for g := range 6 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := range 15 {
				payload := fmt.Sprintf(`{"accept_downloads":%t,"ytdlp_timeout_seconds":%d,"max_concurrent_downloads":%d,"audio_format":%q}`,
					(i%2 == 0), 30+(i%50), 2+(id%4), AllowedAudioFormats[(id+i)%len(AllowedAudioFormats)])
				req, _ := http.NewRequest(http.MethodPatch, adminBaseURL+"/admin/v1/settings", strings.NewReader(payload))
				req.Header.Set("Authorization", "Bearer "+testAdminToken)
				req.Header.Set("Content-Type", "application/json")
				resp, err := client.Do(req)
				if err != nil {
					t.Errorf("admin PATCH error: %v", err)
					return
				}
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Errorf("admin PATCH status %d", resp.StatusCode)
					return
				}

				gReq, _ := http.NewRequest(http.MethodGet, adminBaseURL+"/admin/v1/settings", nil)
				gReq.Header.Set("Authorization", "Bearer "+testAdminToken)
				gResp, err := client.Do(gReq)
				if err != nil {
					t.Errorf("admin GET error: %v", err)
					return
				}
				_ = gResp.Body.Close()

				form := url.Values{"url": {"https://www.youtube.com/watch?v=dQw4w9WgXcQ"}}
				dResp, err := client.PostForm(pubBaseURL+"/download", form)
				if err != nil {
					t.Errorf("public POST /download error: %v", err)
					return
				}
				_, _ = io.ReadAll(dResp.Body)
				_ = dResp.Body.Close()
				switch dResp.StatusCode {
				case http.StatusOK, http.StatusServiceUnavailable, http.StatusTooManyRequests:
				default:
					t.Errorf("unexpected download status %d", dResp.StatusCode)
					return
				}
			}
		}(g)
	}
	wg.Wait()

	if active := st.ActiveDownloads(); active != 0 {
		t.Fatalf("expected 0 active downloads after race test, got %d", active)
	}
}

func TestPublicServerLongRunnerSurvivesReadTimeout(t *testing.T) {
	pubDir := t.TempDir()
	st := NewSettingsStore()
	app := newAppServer(pubDir, st, func(_ context.Context, outputPattern, audioFormat, _, _, _ string) error {
		// Longer than ReadTimeout (40ms) to confirm ParseForm() clears ReadDeadline
		// and does not cancel r.Context() while yt-dlp is executing.
		time.Sleep(120 * time.Millisecond)
		return os.WriteFile(filepath.Join(filepath.Dir(outputPattern), "slow."+audioFormat), []byte("ok"), 0o600)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pubSrv := &http.Server{
		Handler:           app.handler(),
		ReadHeaderTimeout: 20 * time.Millisecond,
		ReadTimeout:       40 * time.Millisecond,
		IdleTimeout:       5 * time.Second,
	}
	defer pubSrv.Close()
	go func() {
		_ = pubSrv.Serve(ln)
	}()

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.PostForm("http://"+ln.Addr().String()+"/download", url.Values{
		"url": {"https://www.youtube.com/watch?v=dQw4w9WgXcQ"},
	})
	if err != nil {
		t.Fatalf("POST /download failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("expected 200 'ok' even when runner exceeds ReadTimeout, got %d %q", resp.StatusCode, string(body))
	}
}
