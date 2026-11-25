package main

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
)

const (
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
	AcceptDownloads        bool   `json:"accept_downloads"`
	YtDlpTimeoutSeconds    int    `json:"ytdlp_timeout_seconds"`
	MaxConcurrentDownloads int    `json:"max_concurrent_downloads"`
	AudioFormat            string `json:"audio_format"`
}

// SettingsPatch represents a partial update to RuntimeSettings.
type SettingsPatch struct {
	AcceptDownloads        *bool   `json:"accept_downloads"`
	YtDlpTimeoutSeconds    *int    `json:"ytdlp_timeout_seconds"`
	MaxConcurrentDownloads *int    `json:"max_concurrent_downloads"`
	AudioFormat            *string `json:"audio_format"`
}

// DefaultSettings returns the initial runtime settings for audown.
func DefaultSettings() RuntimeSettings {
	return RuntimeSettings{
		AcceptDownloads:        defaultAcceptDownloads,
		YtDlpTimeoutSeconds:    defaultYtDlpTimeoutSeconds,
		MaxConcurrentDownloads: defaultMaxConcurrentDownloads,
		AudioFormat:            defaultAudioFormat,
	}
}

// SettingsStore provides thread-safe runtime configuration and download slot accounting.
type SettingsStore struct {
	mu              sync.RWMutex
	current         RuntimeSettings
	activeDownloads int
}

// NewSettingsStore initializes a SettingsStore with default runtime settings.
func NewSettingsStore() *SettingsStore {
	return &SettingsStore{
		current: DefaultSettings(),
	}
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

// Update validates and atomically applies patch, returning the resulting settings snapshot.
func (s *SettingsStore) Update(patch SettingsPatch) (RuntimeSettings, error) {
	if err := patch.ValidateAndNormalize(); err != nil {
		return RuntimeSettings{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if patch.AcceptDownloads != nil {
		s.current.AcceptDownloads = *patch.AcceptDownloads
	}
	if patch.YtDlpTimeoutSeconds != nil {
		s.current.YtDlpTimeoutSeconds = *patch.YtDlpTimeoutSeconds
	}
	if patch.MaxConcurrentDownloads != nil {
		s.current.MaxConcurrentDownloads = *patch.MaxConcurrentDownloads
	}
	if patch.AudioFormat != nil {
		s.current.AudioFormat = *patch.AudioFormat
	}
	return s.current, nil
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
