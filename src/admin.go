package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

const (
	adminServiceName  = "audown"
	adminAPIVersion   = "0.1.0"
	maxAdminBodyBytes = 16 << 10
)

// AdminServer serves the internal-only :9090 Admin API consumed by admin.cubus.sh.
type AdminServer struct {
	settings  *SettingsStore
	tokenHash [32]byte
	allowCIDR *netip.Prefix
}

// NewAdminServer constructs a validated AdminServer instance.
func NewAdminServer(settings *SettingsStore, token string, allowCIDR *netip.Prefix) (*AdminServer, error) {
	if settings == nil {
		return nil, errors.New("settings store must not be nil")
	}
	if err := ValidateAdminToken(token); err != nil {
		return nil, err
	}
	if allowCIDR != nil {
		if allowCIDR.Bits() == 0 {
			return nil, errors.New("allowCIDR must not be a /0 prefix")
		}
		if allowCIDR.Addr().Is4In6() {
			return nil, errors.New("allowCIDR must not be IPv4-mapped IPv6")
		}
		masked := allowCIDR.Masked()
		allowCIDR = &masked
	}
	return &AdminServer{
		settings:  settings,
		tokenHash: sha256.Sum256([]byte(token)),
		allowCIDR: allowCIDR,
	}, nil
}

// Handler returns the guarded HTTP handler for the Admin API.
func (s *AdminServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/v1/manifest", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeAdminError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleManifest(w, r)
	})
	mux.HandleFunc("/admin/v1/settings", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.handleGetSettings(w, r)
		case http.MethodPatch:
			s.handlePatchSettings(w, r)
		default:
			w.Header().Set("Allow", http.MethodGet+", "+http.MethodPatch)
			writeAdminError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeAdminError(w, http.StatusNotFound, "admin endpoint not found")
	})
	return s.guardMiddleware(mux)
}

func (s *AdminServer) guardMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")

		peerHost, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			peerHost = r.RemoteAddr
		}
		peerIP, err := netip.ParseAddr(strings.TrimSpace(peerHost))
		if err != nil {
			writeAdminError(w, http.StatusForbidden, "invalid peer address")
			return
		}
		peerIP = peerIP.Unmap()
		if s.allowCIDR != nil {
			if !s.allowCIDR.Contains(peerIP) {
				writeAdminError(w, http.StatusForbidden, "peer outside allowed admin subnet")
				return
			}
		} else if !peerIP.IsLoopback() {
			writeAdminError(w, http.StatusForbidden, "admin API restricted to loopback")
			return
		}

		if !s.authorizeBearer(r) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="audown-admin"`)
			writeAdminError(w, http.StatusUnauthorized, "missing or invalid admin bearer token")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *AdminServer) authorizeBearer(r *http.Request) bool {
	authHeaders := r.Header.Values("Authorization")
	if len(authHeaders) != 1 {
		return false
	}
	fields := strings.Fields(authHeaders[0])
	if len(fields) != 2 || !strings.EqualFold(fields[0], "bearer") {
		return false
	}
	// Hash both inputs so ConstantTimeCompare always compares fixed 32-byte digests.
	candidateHash := sha256.Sum256([]byte(fields[1]))
	return subtle.ConstantTimeCompare(candidateHash[:], s.tokenHash[:]) == 1
}

func (s *AdminServer) handleManifest(w http.ResponseWriter, _ *http.Request) {
	writeAdminJSON(w, http.StatusOK, map[string]any{
		"service":      adminServiceName,
		"version":      adminAPIVersion,
		"capabilities": []string{"settings"},
		"endpoints": map[string]string{
			"settings_get":    "GET /admin/v1/settings",
			"settings_update": "PATCH /admin/v1/settings",
		},
		"settings_schema": []map[string]any{
			{
				"key":   "accept_downloads",
				"label": "Accept new downloads",
				"type":  "bool",
				"help":  "When disabled, POST /download rejects new requests with 503 Service Unavailable while keeping the web UI and healthcheck online.",
			},
			{
				"key":   "ytdlp_timeout_seconds",
				"label": "yt-dlp timeout (seconds)",
				"type":  "int",
				"min":   minYtDlpTimeoutSeconds,
				"max":   maxYtDlpTimeoutSeconds,
				"help":  fmt.Sprintf("Maximum execution time allowed per yt-dlp download before terminating the process group (%d-%d seconds; note cubus.sh nginx-proxy enforces proxy_read_timeout 120s unless raised).", minYtDlpTimeoutSeconds, maxYtDlpTimeoutSeconds),
			},
			{
				"key":   "max_concurrent_downloads",
				"label": "Max concurrent downloads",
				"type":  "int",
				"min":   minConcurrentDownloads,
				"max":   maxConcurrentDownloads,
				"help":  fmt.Sprintf("Maximum simultaneous yt-dlp downloads allowed before returning 429 Too Many Requests (%d-%d).", minConcurrentDownloads, maxConcurrentDownloads),
			},
			{
				"key":   "audio_format",
				"label": "Audio format",
				"type":  "string",
				"help":  fmt.Sprintf("Target yt-dlp --audio-format output format (%s).", strings.Join(AllowedAudioFormats, ", ")),
			},
		},
	})
}

func (s *AdminServer) handleGetSettings(w http.ResponseWriter, _ *http.Request) {
	writeAdminJSON(w, http.StatusOK, s.settings.Get())
}

func (s *AdminServer) handlePatchSettings(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeAdminError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeAdminError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		writeAdminError(w, http.StatusBadRequest, "settings patch must be a JSON object")
		return
	}

	var patch SettingsPatch
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&patch); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid settings patch JSON")
		return
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeAdminError(w, http.StatusBadRequest, "trailing JSON tokens in settings patch")
		return
	}

	var rawFields map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawFields); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid settings patch JSON")
		return
	}
	for k, raw := range rawFields {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			writeAdminError(w, http.StatusBadRequest, fmt.Sprintf("%s must not be null", k))
			return
		}
	}

	updated, err := s.settings.Update(patch)
	if err != nil {
		writeAdminError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeAdminJSON(w, http.StatusOK, updated)
}

func writeAdminError(w http.ResponseWriter, status int, msg string) {
	writeAdminJSON(w, status, map[string]string{"error": msg})
}

func writeAdminJSON(w http.ResponseWriter, status int, v any) {
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
