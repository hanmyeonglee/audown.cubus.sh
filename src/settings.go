package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
)

const (
	defaultRequireAuth         = true
	defaultAcceptDownloads     = true
	defaultYtDlpTimeoutSeconds = 110
	minYtDlpTimeoutSeconds     = 10
	maxYtDlpTimeoutSeconds     = 600

	defaultMaxConcurrentDownloads = 4
	minConcurrentDownloads        = 1
	maxConcurrentDownloads        = 32

	defaultAudioFormat = "mp3"
)

var (
	// AllowedAudioFormats defines the permitted yt-dlp --audio-format values.
	AllowedAudioFormats = []string{"mp3", "m4a", "opus", "flac", "wav"}

	errDownloadsPaused  = errors.New("downloads are currently paused")
	errDownloadCapacity = errors.New("max concurrent downloads reached")
)

// RuntimeSettings holds the live, admin-configurable runtime knobs for audown.
type RuntimeSettings struct {
	RequireAuth            bool   `json:"require_auth"`
	AcceptDownloads        bool   `json:"accept_downloads"`
	YtDlpTimeoutSeconds    int    `json:"ytdlp_timeout_seconds"`
	MaxConcurrentDownloads int    `json:"max_concurrent_downloads"`
	AudioFormat            string `json:"audio_format"`
}

func (r RuntimeSettings) toMap() map[string]any {
	return map[string]any{
		"require_auth":             r.RequireAuth,
		"accept_downloads":         r.AcceptDownloads,
		"ytdlp_timeout_seconds":    r.YtDlpTimeoutSeconds,
		"max_concurrent_downloads": r.MaxConcurrentDownloads,
		"audio_format":             r.AudioFormat,
	}
}

// SettingsPatch represents a partial update to RuntimeSettings.
type SettingsPatch struct {
	RequireAuth            *bool   `json:"require_auth"`
	AcceptDownloads        *bool   `json:"accept_downloads"`
	YtDlpTimeoutSeconds    *int    `json:"ytdlp_timeout_seconds"`
	MaxConcurrentDownloads *int    `json:"max_concurrent_downloads"`
	AudioFormat            *string `json:"audio_format"`
}

// DefaultSettings returns the initial runtime settings for audown.
func DefaultSettings() RuntimeSettings {
	return RuntimeSettings{
		RequireAuth:            defaultRequireAuth,
		AcceptDownloads:        defaultAcceptDownloads,
		YtDlpTimeoutSeconds:    defaultYtDlpTimeoutSeconds,
		MaxConcurrentDownloads: defaultMaxConcurrentDownloads,
		AudioFormat:            defaultAudioFormat,
	}
}

// SettingsStore provides thread-safe runtime configuration, DB persistence, and download slot accounting.
type SettingsStore struct {
	updateMu        sync.Mutex
	mu              sync.RWMutex
	current         RuntimeSettings
	activeDownloads int
	store           Store
}

// NewSettingsStore initializes an in-memory SettingsStore with default runtime settings.
func NewSettingsStore() *SettingsStore {
	return &SettingsStore{
		current: DefaultSettings(),
	}
}

// NewSettingsStoreWithStore initializes a SettingsStore backed by persistent Store.
func NewSettingsStoreWithStore(store Store) *SettingsStore {
	return &SettingsStore{
		current: DefaultSettings(),
		store:   store,
	}
}

// Load hydrates runtime settings from app_settings in PostgreSQL.
func (s *SettingsStore) Load(ctx context.Context) error {
	if s.store == nil {
		return nil
	}
	raw, err := s.store.LoadSettings(ctx)
	if err != nil {
		return err
	}
	next := DefaultSettings()
	var patch SettingsPatch
	if v, ok := raw["require_auth"]; ok {
		var b bool
		if err := json.Unmarshal(v, &b); err == nil {
			patch.RequireAuth = &b
		}
	}
	if v, ok := raw["accept_downloads"]; ok {
		var b bool
		if err := json.Unmarshal(v, &b); err == nil {
			patch.AcceptDownloads = &b
		}
	}
	if v, ok := raw["ytdlp_timeout_seconds"]; ok {
		var n int
		if err := json.Unmarshal(v, &n); err == nil {
			patch.YtDlpTimeoutSeconds = &n
		}
	}
	if v, ok := raw["max_concurrent_downloads"]; ok {
		var n int
		if err := json.Unmarshal(v, &n); err == nil {
			patch.MaxConcurrentDownloads = &n
		}
	}
	if v, ok := raw["audio_format"]; ok {
		var f string
		if err := json.Unmarshal(v, &f); err == nil {
			patch.AudioFormat = &f
		}
	}
	if err := patch.ValidateAndNormalize(); err != nil {
		return fmt.Errorf("invalid persisted app_settings: %w", err)
	}
	applySettingsPatch(&next, patch)

	s.mu.Lock()
	s.current = next
	s.mu.Unlock()
	return nil
}

// Get returns a snapshot of the current runtime settings.
func (s *SettingsStore) Get() RuntimeSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

// ActiveDownloads returns the number of currently running download jobs.
func (s *SettingsStore) ActiveDownloads() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeDownloads
}

// IsAcceptingDownloads reports whether downloads are currently enabled.
func (s *SettingsStore) IsAcceptingDownloads() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current.AcceptDownloads
}

// IsRequireAuth reports whether Passkey authentication is currently required.
func (s *SettingsStore) IsRequireAuth() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current.RequireAuth
}

// ValidateAndNormalize validates every non-nil field in patch and normalizes values.
func (p *SettingsPatch) ValidateAndNormalize() error {
	if p.YtDlpTimeoutSeconds != nil {
		if *p.YtDlpTimeoutSeconds < minYtDlpTimeoutSeconds || *p.YtDlpTimeoutSeconds > maxYtDlpTimeoutSeconds {
			return fmt.Errorf("ytdlp_timeout_seconds must be between %d and %d", minYtDlpTimeoutSeconds, maxYtDlpTimeoutSeconds)
		}
	}
	if p.MaxConcurrentDownloads != nil {
		if *p.MaxConcurrentDownloads < minConcurrentDownloads || *p.MaxConcurrentDownloads > maxConcurrentDownloads {
			return fmt.Errorf("max_concurrent_downloads must be between %d and %d", minConcurrentDownloads, maxConcurrentDownloads)
		}
	}
	if p.AudioFormat != nil {
		normalized := strings.ToLower(strings.TrimSpace(*p.AudioFormat))
		if !slices.Contains(AllowedAudioFormats, normalized) {
			return fmt.Errorf("audio_format must be one of: %s", strings.Join(AllowedAudioFormats, ", "))
		}
		p.AudioFormat = &normalized
	}
	return nil
}

func applySettingsPatch(dst *RuntimeSettings, patch SettingsPatch) {
	if patch.RequireAuth != nil {
		dst.RequireAuth = *patch.RequireAuth
	}
	if patch.AcceptDownloads != nil {
		dst.AcceptDownloads = *patch.AcceptDownloads
	}
	if patch.YtDlpTimeoutSeconds != nil {
		dst.YtDlpTimeoutSeconds = *patch.YtDlpTimeoutSeconds
	}
	if patch.MaxConcurrentDownloads != nil {
		dst.MaxConcurrentDownloads = *patch.MaxConcurrentDownloads
	}
	if patch.AudioFormat != nil {
		dst.AudioFormat = *patch.AudioFormat
	}
}

// Update validates and atomically applies patch, returning the resulting settings snapshot.
func (s *SettingsStore) Update(patch SettingsPatch) (RuntimeSettings, error) {
	return s.UpdateContext(context.Background(), patch)
}

// UpdateContext validates, persists (if backed by a Store), and applies patch.
func (s *SettingsStore) UpdateContext(ctx context.Context, patch SettingsPatch) (RuntimeSettings, error) {
	if err := patch.ValidateAndNormalize(); err != nil {
		return RuntimeSettings{}, err
	}

	s.updateMu.Lock()
	defer s.updateMu.Unlock()

	s.mu.RLock()
	next := s.current
	s.mu.RUnlock()

	applySettingsPatch(&next, patch)

	if s.store != nil {
		if err := s.store.SaveSettings(ctx, next.toMap()); err != nil {
			return RuntimeSettings{}, fmt.Errorf("persist settings: %w", err)
		}
	}

	s.mu.Lock()
	s.current = next
	s.mu.Unlock()
	return next, nil
}

// AcquireDownload atomically verifies that downloads are enabled and capacity is available,
// returning a settings snapshot and an idempotent release function.
func (s *SettingsStore) AcquireDownload() (RuntimeSettings, func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.current.AcceptDownloads {
		return RuntimeSettings{}, nil, errDownloadsPaused
	}
	if s.activeDownloads >= s.current.MaxConcurrentDownloads {
		return RuntimeSettings{}, nil, errDownloadCapacity
	}

	s.activeDownloads++
	snap := s.current
	release := sync.OnceFunc(func() {
		s.mu.Lock()
		if s.activeDownloads > 0 {
			s.activeDownloads--
		}
		s.mu.Unlock()
	})
	return snap, release, nil
}
