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
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	adminServiceName   = "audown"
	adminAPIVersion    = "0.2.0"
	maxAdminBodyBytes  = 16 << 10
	defaultInviteTTL   = 168 // 7 days
	minInviteTTLHours  = 1
	maxInviteTTLHours  = 720 // 30 days
	maxDisplayNameRune = 64
	maxCreatedByRune   = 64
)

// AdminServer serves the internal-only :9090 Admin API consumed by admin.cubus.sh.
type AdminServer struct {
	settings      *SettingsStore
	store         Store
	publicBaseURL string
	tokenHash     [32]byte
	allowCIDR     *netip.Prefix
	nowFn         func() time.Time
}

// NewAdminServer constructs a validated AdminServer instance.
func NewAdminServer(settings *SettingsStore, store Store, publicBaseURL, token string, allowCIDR *netip.Prefix) (*AdminServer, error) {
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
	baseURL := strings.TrimRight(strings.TrimSpace(publicBaseURL), "/")
	if baseURL == "" {
		baseURL = DefaultPublicBaseURL
	}
	return &AdminServer{
		settings:      settings,
		store:         store,
		publicBaseURL: baseURL,
		tokenHash:     sha256.Sum256([]byte(token)),
		allowCIDR:     allowCIDR,
		nowFn:         func() time.Time { return time.Now().UTC() },
	}, nil
}

func (s *AdminServer) now() time.Time {
	if s.nowFn != nil {
		return s.nowFn().UTC()
	}
	return time.Now().UTC()
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
	mux.HandleFunc("/admin/v1/users", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeAdminError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleListUsers(w, r)
	})
	mux.HandleFunc("/admin/v1/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPatch:
			s.handlePatchUser(w, r)
		case http.MethodDelete:
			s.handleDeleteUser(w, r)
		default:
			w.Header().Set("Allow", http.MethodPatch+", "+http.MethodDelete)
			writeAdminError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	})
	mux.HandleFunc("/admin/v1/users/{id}/sessions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.Header().Set("Allow", http.MethodDelete)
			writeAdminError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleDeleteUserSessions(w, r)
	})
	mux.HandleFunc("/admin/v1/invites", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.handleListInvites(w, r)
		case http.MethodPost:
			s.handleCreateInvite(w, r)
		default:
			w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
			writeAdminError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	})
	mux.HandleFunc("/admin/v1/invites/{id}", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.Header().Set("Allow", http.MethodDelete)
			writeAdminError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleDeleteInvite(w, r)
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
		"capabilities": []string{"settings", "users", "invites"},
		"user_capabilities": map[string]bool{
			"create":         false,
			"approve":        false,
			"toggle_status":  true,
			"reset_password": false,
			"change_role":    false,
			"delete":         true,
			"sessions":       true,
			"invites":        true,
		},
		"user_columns": []map[string]any{
			{"key": "active_sessions", "label": "Sessions"},
			{"key": "last_login_at", "label": "Last Login", "format": "datetime"},
		},
		"endpoints": map[string]string{
			"settings_get":         "GET /admin/v1/settings",
			"settings_update":      "PATCH /admin/v1/settings",
			"users_list":           "GET /admin/v1/users",
			"user_update":          "PATCH /admin/v1/users/{id}",
			"user_delete":          "DELETE /admin/v1/users/{id}",
			"user_sessions_delete": "DELETE /admin/v1/users/{id}/sessions",
			"invites_list":         "GET /admin/v1/invites",
			"invites_create":       "POST /admin/v1/invites",
			"invite_delete":        "DELETE /admin/v1/invites/{id}",
		},
		"settings_schema": []map[string]any{
			{
				"key":   "require_auth",
				"label": "Require Passkey authentication",
				"type":  "bool",
				"help":  "When enabled, visitors must sign in with an enrolled Passkey before viewing the UI or downloading audio.",
			},
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

func decodeAdminJSONObject(w http.ResponseWriter, r *http.Request, dst any, rejectNulls bool) (int, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminBodyBytes)
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
		return http.StatusBadRequest, errors.New("invalid JSON body")
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return http.StatusBadRequest, errors.New("trailing JSON tokens in request body")
	}

	if rejectNulls {
		var rawFields map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &rawFields); err != nil {
			return http.StatusBadRequest, errors.New("invalid JSON body")
		}
		for k, raw := range rawFields {
			if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
				return http.StatusBadRequest, fmt.Errorf("%s must not be null", k)
			}
		}
	}
	return 0, nil
}

func (s *AdminServer) handlePatchSettings(w http.ResponseWriter, r *http.Request) {
	var patch SettingsPatch
	if status, err := decodeAdminJSONObject(w, r, &patch, true); err != nil {
		writeAdminError(w, status, err.Error())
		return
	}

	updated, err := s.settings.UpdateContext(r.Context(), patch)
	if err != nil {
		if strings.HasPrefix(err.Error(), "persist settings:") {
			writeAdminError(w, http.StatusInternalServerError, "failed to persist settings")
			return
		}
		writeAdminError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeAdminJSON(w, http.StatusOK, updated)
}

func (s *AdminServer) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeAdminError(w, http.StatusServiceUnavailable, "database store unavailable")
		return
	}
	statusFilter := strings.TrimSpace(r.URL.Query().Get("status"))
	if statusFilter != "" && statusFilter != UserStatusActive && statusFilter != UserStatusDisabled {
		writeAdminError(w, http.StatusBadRequest, "invalid status filter (expected active or disabled)")
		return
	}
	users, err := s.store.ListUsers(r.Context(), statusFilter, s.now())
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "failed to list users")
		return
	}
	if users == nil {
		users = []UserSummary{}
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"users": users})
}

type patchUserRequest struct {
	Status string `json:"status"`
}

func (s *AdminServer) handlePatchUser(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeAdminError(w, http.StatusServiceUnavailable, "database store unavailable")
		return
	}
	userID, err := uuid.Parse(strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	var req patchUserRequest
	if status, err := decodeAdminJSONObject(w, r, &req, true); err != nil {
		writeAdminError(w, status, err.Error())
		return
	}
	nextStatus := strings.TrimSpace(req.Status)
	if nextStatus != UserStatusActive && nextStatus != UserStatusDisabled {
		writeAdminError(w, http.StatusBadRequest, "status must be active or disabled")
		return
	}

	updated, err := s.store.UpdateUserStatus(r.Context(), userID, nextStatus, s.now())
	if errors.Is(err, ErrNotFound) {
		writeAdminError(w, http.StatusNotFound, "user not found")
		return
	}
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "failed to update user")
		return
	}
	writeAdminJSON(w, http.StatusOK, updated)
}

func (s *AdminServer) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeAdminError(w, http.StatusServiceUnavailable, "database store unavailable")
		return
	}
	userID, err := uuid.Parse(strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	if err := s.store.DeleteUser(r.Context(), userID); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeAdminError(w, http.StatusNotFound, "user not found")
			return
		}
		writeAdminError(w, http.StatusInternalServerError, "failed to delete user")
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{
		"deleted": true,
		"id":      userID.String(),
	})
}

func (s *AdminServer) handleDeleteUserSessions(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeAdminError(w, http.StatusServiceUnavailable, "database store unavailable")
		return
	}
	userID, err := uuid.Parse(strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	revoked, err := s.store.DeleteSessionsByUserID(r.Context(), userID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeAdminError(w, http.StatusNotFound, "user not found")
			return
		}
		writeAdminError(w, http.StatusInternalServerError, "failed to revoke user sessions")
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{
		"revoked": revoked,
		"user_id": userID.String(),
	})
}

func (s *AdminServer) handleListInvites(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeAdminError(w, http.StatusServiceUnavailable, "database store unavailable")
		return
	}
	records, err := s.store.ListInvites(r.Context())
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "failed to list invites")
		return
	}
	now := s.now()
	views := make([]InviteView, 0, len(records))
	for _, inv := range records {
		views = append(views, inv.View(now))
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"invites": views})
}

type createInviteRequest struct {
	DisplayName string `json:"display_name"`
	TTLHours    *int   `json:"ttl_hours"`
	CreatedBy   string `json:"created_by"`
}

func containsControlChar(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func (s *AdminServer) handleCreateInvite(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeAdminError(w, http.StatusServiceUnavailable, "database store unavailable")
		return
	}
	var req createInviteRequest
	if status, err := decodeAdminJSONObject(w, r, &req, true); err != nil {
		writeAdminError(w, status, err.Error())
		return
	}

	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" || utf8.RuneCountInString(displayName) > maxDisplayNameRune || containsControlChar(displayName) {
		writeAdminError(w, http.StatusBadRequest, fmt.Sprintf("display_name must be 1..%d printable characters", maxDisplayNameRune))
		return
	}

	ttlHours := defaultInviteTTL
	if req.TTLHours != nil {
		ttlHours = *req.TTLHours
	}
	if ttlHours < minInviteTTLHours || ttlHours > maxInviteTTLHours {
		writeAdminError(w, http.StatusBadRequest, fmt.Sprintf("ttl_hours must be between %d and %d", minInviteTTLHours, maxInviteTTLHours))
		return
	}

	createdBy := strings.TrimSpace(req.CreatedBy)
	if utf8.RuneCountInString(createdBy) > maxCreatedByRune || containsControlChar(createdBy) {
		writeAdminError(w, http.StatusBadRequest, fmt.Sprintf("created_by must be at most %d printable characters", maxCreatedByRune))
		return
	}

	rawToken, err := newRandomToken()
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "failed to generate invite token")
		return
	}

	now := s.now()
	inv := InviteRecord{
		ID:          uuid.New(),
		TokenHash:   hashToken(rawToken),
		DisplayName: displayName,
		ExpiresAt:   now.Add(time.Duration(ttlHours) * time.Hour),
		CreatedBy:   createdBy,
		CreatedAt:   now,
	}
	if err := s.store.CreateInvite(r.Context(), inv); err != nil {
		writeAdminError(w, http.StatusInternalServerError, "failed to create invite")
		return
	}

	writeAdminJSON(w, http.StatusCreated, map[string]any{
		"invite":     inv.View(now),
		"invite_url": s.publicBaseURL + "/invite/" + rawToken,
	})
}

func (s *AdminServer) handleDeleteInvite(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeAdminError(w, http.StatusServiceUnavailable, "database store unavailable")
		return
	}
	inviteID, err := uuid.Parse(strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid invite id")
		return
	}
	if err := s.store.DeleteUnusedInvite(r.Context(), inviteID); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeAdminError(w, http.StatusNotFound, "invite not found")
			return
		}
		if errors.Is(err, ErrInviteAlreadyUse) {
			writeAdminError(w, http.StatusConflict, "cannot revoke an already used invite")
			return
		}
		writeAdminError(w, http.StatusInternalServerError, "failed to delete invite")
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{
		"deleted": true,
		"id":      inviteID.String(),
	})
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
