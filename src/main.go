package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	badRequestMsg              = "잘못된 입력입니다. 다시 시도해주세요."
	internalServerErrorMsg     = "오류가 발생했습니다. 다시 시도해주세요."
	downloadTimeoutMsg         = "처리에 너무 긴 시간이 걸립니다. 다른 영상이나 짧은 구간을 시도해주세요."
	downloadResponseCookieName = "audown-download-response"
	maxDownloadFormBytes       = 16 << 10
	maxStderrBytes             = 64 << 10
	cmdWaitDelay               = 5 * time.Second
	downloadWriteIdleTimeout   = 30 * time.Second
	shutdownTimeout            = 12 * time.Second
)

var (
	timeNotification     = regexp.MustCompile(`^\d{2,}:[0-5]\d:[0-5]\d$`)
	downloadTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)
	videoIDParamPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

	audioMIMETypes = map[string]string{
		".mp3":  "audio/mpeg",
		".m4a":  "audio/mp4",
		".opus": "audio/opus",
		".flac": "audio/flac",
		".wav":  "audio/wav",
	}

	allowedSubprocessEnvKeys = []string{
		"PATH",
		"LANG",
		"LC_ALL",
		"TZ",
		"SSL_CERT_FILE",
		"SSL_CERT_DIR",
		"NODE_EXTRA_CA_CERTS",
	}
)

type downloadRunner func(ctx context.Context, outputPattern, audioFormat, startTime, endTime, videoURL string) error

type appServer struct {
	publicHandler http.Handler
	settings      *SettingsStore
	runner        downloadRunner
	badReqURL     string
	internalURL   string
	timeoutURL    string
}

func newAppServer(publicDir string, settings *SettingsStore, runner downloadRunner) *appServer {
	if runner == nil {
		runner = runDownloadCommand
	}
	fileSrv := http.FileServer(http.Dir(publicDir))
	return &appServer{
		publicHandler: rejectDotSegments(fileSrv),
		settings:      settings,
		runner:        runner,
		badReqURL:     "/?err=" + url.QueryEscape(badRequestMsg),
		internalURL:   "/?err=" + url.QueryEscape(internalServerErrorMsg),
		timeoutURL:    "/?err=" + url.QueryEscape(downloadTimeoutMsg),
	}
}

func rejectDotSegments(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if containsDotSegment(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func containsDotSegment(urlPath string) bool {
	cleaned := path.Clean("/" + urlPath)
	for _, seg := range strings.Split(cleaned, "/") {
		if seg != "" && strings.HasPrefix(seg, ".") {
			return true
		}
	}
	return false
}

func (a *appServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.publicHandler.ServeHTTP(w, r)
	})
	mux.HandleFunc("/download", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.handleDownload(w, r)
	})
	return logging(mux)
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info(
			"HTTP Request",
			"method", r.Method,
			"path", r.URL.Path,
			"remote", r.RemoteAddr,
		)

		next.ServeHTTP(w, r)
	})
}

func isUrlFormatRight(rawURL string) bool {
	if rawURL == "" || strings.TrimSpace(rawURL) != rawURL {
		return false
	}
	for i := range len(rawURL) {
		b := rawURL[i]
		if b <= 0x20 || b == 0x7f {
			return false
		}
	}

	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return false
	}

	switch u.Hostname() {
	case "www.youtube.com":
		if u.Path == "/watch" {
			return videoIDParamPattern.MatchString(u.Query().Get("v"))
		}
		parts := splitNonEmptyPath(u.Path)
		if len(parts) != 2 {
			return false
		}
		switch parts[0] {
		case "shorts", "embed", "live", "v":
			return videoIDParamPattern.MatchString(parts[1])
		default:
			return false
		}
	case "youtu.be":
		parts := splitNonEmptyPath(u.Path)
		return len(parts) == 1 && videoIDParamPattern.MatchString(parts[0])
	default:
		return false
	}
}

func splitNonEmptyPath(urlPath string) []string {
	trimmed := strings.Trim(urlPath, "/")
	if trimmed == "" {
		return nil
	}
	parts := strings.Split(trimmed, "/")
	for _, p := range parts {
		if p == "" {
			return nil
		}
	}
	return parts
}

func parseTimeSeconds(expr string) (int, bool) {
	if !timeNotification.MatchString(expr) {
		return 0, false
	}
	parts := strings.Split(expr, ":")
	if len(parts) != 3 {
		return 0, false
	}
	h, errH := strconv.Atoi(parts[0])
	m, errM := strconv.Atoi(parts[1])
	s, errS := strconv.Atoi(parts[2])
	if errH != nil || errM != nil || errS != nil {
		return 0, false
	}
	return h*3600 + m*60 + s, true
}

func isTimeExpressionRight(startTime string, endTime string) bool {
	var startSec, endSec int
	if startTime != "" {
		var ok bool
		startSec, ok = parseTimeSeconds(startTime)
		if !ok {
			return false
		}
	}
	if endTime != "" {
		var ok bool
		endSec, ok = parseTimeSeconds(endTime)
		if !ok {
			return false
		}
	}
	if startTime != "" && endTime != "" && startSec >= endSec {
		return false
	}
	return true
}

func killProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return os.ErrProcessDone
	}

	err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}

func sanitizedCommandEnv(getenv func(string) string) []string {
	tmpDir := strings.TrimSpace(getenv("TMPDIR"))
	if tmpDir == "" {
		tmpDir = "/tmp"
	}
	env := []string{
		"HOME=/tmp",
		"XDG_CACHE_HOME=/tmp",
		"TMPDIR=" + tmpDir,
	}
	for _, key := range allowedSubprocessEnvKeys {
		if val := getenv(key); val != "" {
			env = append(env, key+"="+val)
		}
	}
	return env
}

func buildYtDlpArgs(outputPattern, audioFormat, startTime, endTime, videoURL string) []string {
	args := []string{
		"-o",
		outputPattern,
		"-x",
		"--audio-format=" + audioFormat,
		"--no-continue",
		"--ignore-errors",
		"--no-playlist",
		"--no-cache-dir",
		"--js-runtimes",
		"node",
	}
	if !(startTime == "" && endTime == "") {
		args = append(args, "--download-sections", "*"+startTime+"-"+endTime)
	}
	args = append(args, "--", videoURL)
	return args
}

type limitedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if l.buf.Len() < l.limit {
		remain := l.limit - l.buf.Len()
		if len(p) > remain {
			_, _ = l.buf.Write(p[:remain])
			l.truncated = true
		} else {
			_, _ = l.buf.Write(p)
		}
	} else if len(p) > 0 {
		l.truncated = true
	}
	return len(p), nil
}

func (l *limitedBuffer) String() string {
	if l.truncated {
		return l.buf.String() + "\n...(stderr truncated)"
	}
	return l.buf.String()
}

func runDownloadCommand(ctx context.Context, outputPattern, audioFormat, startTime, endTime, videoURL string) error {
	args := buildYtDlpArgs(outputPattern, audioFormat, startTime, endTime, videoURL)
	cmd := exec.CommandContext(ctx, "yt-dlp", args...)
	cmd.Env = sanitizedCommandEnv(os.Getenv)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = cmdWaitDelay
	cmd.Cancel = func() error {
		return killProcessGroup(cmd)
	}

	stderr := &limitedBuffer{limit: maxStderrBytes}
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			slog.Warn("Server Timeout", "yt-dlp stderr", stderr.String())
		} else {
			slog.Error("Server Error", "error", err, "yt-dlp stderr", stderr.String())
		}
		return err
	}
	return nil
}

func audioContentType(filename, audioFormat string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	if ext == "" && audioFormat != "" {
		ext = "." + strings.ToLower(audioFormat)
	}
	if ct, ok := audioMIMETypes[ext]; ok {
		return ct
	}
	if ct := mime.TypeByExtension(ext); ct != "" {
		return ct
	}
	return "application/octet-stream"
}

func writeMaintenanceUnavailable(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Retry-After", "60")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte("Downloads are temporarily paused for maintenance.\n"))
}

func writeDownloadBusy(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Retry-After", "5")
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write([]byte("Too many concurrent downloads; please try again shortly.\n"))
}

type deadlineResponseWriter struct {
	w  http.ResponseWriter
	rc *http.ResponseController
}

func (dw *deadlineResponseWriter) Header() http.Header         { return dw.w.Header() }
func (dw *deadlineResponseWriter) WriteHeader(code int)        { dw.w.WriteHeader(code) }
func (dw *deadlineResponseWriter) Unwrap() http.ResponseWriter { return dw.w }

func (dw *deadlineResponseWriter) Write(p []byte) (int, error) {
	_ = dw.rc.SetWriteDeadline(time.Now().Add(downloadWriteIdleTimeout))
	return dw.w.Write(p)
}

func (a *appServer) handleDownload(w http.ResponseWriter, r *http.Request) {
	if !a.settings.IsAcceptingDownloads() {
		writeMaintenanceUnavailable(w)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxDownloadFormBytes)
	if parseErr := r.ParseForm(); parseErr != nil {
		slog.Error("Bad Request", "error", parseErr)
		http.Redirect(w, r, a.badReqURL, http.StatusSeeOther)
		return
	}

	rawURL := r.PostForm.Get("url")
	if rawURL == "" {
		slog.Error("Bad Request", "error", "empty url field")
		http.Redirect(w, r, a.badReqURL, http.StatusSeeOther)
		return
	}
	if !isUrlFormatRight(rawURL) {
		slog.Error("Bad Request", "error", "invalid url format", "url", rawURL)
		http.Redirect(w, r, a.badReqURL, http.StatusSeeOther)
		return
	}

	startTime := r.PostForm.Get("startTime")
	endTime := r.PostForm.Get("endTime")
	downloadToken := r.PostForm.Get("downloadToken")
	if !isTimeExpressionRight(startTime, endTime) {
		slog.Error("Bad Request", "error", "time expression is invalid", "startTime", startTime, "endTime", endTime)
		http.Redirect(w, r, a.badReqURL, http.StatusSeeOther)
		return
	}

	snap, release, acquireErr := a.settings.AcquireDownload()
	if acquireErr != nil {
		if errors.Is(acquireErr, errDownloadsPaused) {
			writeMaintenanceUnavailable(w)
			return
		}
		writeDownloadBusy(w)
		return
	}
	defer release()

	tempDirPath, tempDirErr := os.MkdirTemp("", "download-")
	if tempDirErr != nil {
		slog.Error("Server Error", "error", tempDirErr)
		http.Redirect(w, r, a.internalURL, http.StatusSeeOther)
		return
	}
	defer os.RemoveAll(tempDirPath)

	musicDownloadPath := filepath.Join(tempDirPath, "%(title)s.%(ext)s")
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(snap.YtDlpTimeoutSeconds)*time.Second)
	defer cancel()

	if cmdErr := a.runner(ctx, musicDownloadPath, snap.AudioFormat, startTime, endTime, rawURL); cmdErr != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			http.Redirect(w, r, a.timeoutURL, http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, a.internalURL, http.StatusSeeOther)
		return
	}

	files, musicCheckErr := os.ReadDir(tempDirPath)
	if musicCheckErr != nil {
		slog.Error("Server Error", "error", musicCheckErr)
		http.Redirect(w, r, a.internalURL, http.StatusSeeOther)
		return
	}
	if len(files) != 1 || files[0].IsDir() {
		slog.Error("Server Error", "error", "unexpected output file count", "file_count", len(files))
		http.Redirect(w, r, a.internalURL, http.StatusSeeOther)
		return
	}
	info, infoErr := files[0].Info()
	if infoErr != nil || !info.Mode().IsRegular() {
		slog.Error("Server Error", "error", infoErr)
		http.Redirect(w, r, a.internalURL, http.StatusSeeOther)
		return
	}

	musicName := files[0].Name()
	musicPath := filepath.Join(tempDirPath, musicName)
	cd := mime.FormatMediaType("attachment", map[string]string{"filename": musicName})
	if cd == "" {
		cd = "attachment"
	}
	w.Header().Set("Content-Disposition", cd)
	w.Header().Set("Content-Type", audioContentType(musicName, snap.AudioFormat))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	if downloadTokenPattern.MatchString(downloadToken) {
		http.SetCookie(w, &http.Cookie{
			Name:     downloadResponseCookieName,
			Value:    downloadToken,
			Path:     "/",
			MaxAge:   60,
			SameSite: http.SameSiteLaxMode,
		})
	}

	slog.Info("Music Download", "musicName", musicName)
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(downloadWriteIdleTimeout))
	defer func() {
		_ = rc.SetWriteDeadline(time.Time{})
	}()
	dw := &deadlineResponseWriter{w: w, rc: rc}
	http.ServeFile(dw, r, musicPath)
}

func run() error {
	cfg, err := LoadConfigFromEnv()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if err := ValidatePublicDir(cfg.PublicDir); err != nil {
		return err
	}
	if err := mime.AddExtensionType(".webmanifest", "application/manifest+json"); err != nil {
		return fmt.Errorf("register webmanifest MIME type: %w", err)
	}

	slog.Info("Server start", "config", cfg)

	settings := NewSettingsStore()
	app := newAppServer(cfg.PublicDir, settings, nil)

	sigCtx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()

	var adminSrv *AdminServer
	var adminAddr string
	if cfg.AdminAPIToken != "" {
		adminAddr, err = ResolveBindAddr(cfg.AdminBindCIDR, cfg.AdminPort)
		if err != nil {
			return fmt.Errorf("resolve admin bind address: %w", err)
		}
		adminSrv, err = NewAdminServer(settings, cfg.AdminAPIToken, cfg.AdminAllowCIDR)
		if err != nil {
			return fmt.Errorf("initialize admin server: %w", err)
		}
	}

	publicLn, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen public HTTP %s: %w", cfg.ListenAddr, err)
	}

	publicHTTP := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           app.handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		BaseContext: func(net.Listener) context.Context {
			return sigCtx
		},
	}

	var adminHTTP *http.Server
	var adminLn net.Listener
	if adminSrv != nil {
		adminLn, err = net.Listen("tcp", adminAddr)
		if err != nil {
			_ = publicLn.Close()
			return fmt.Errorf("listen admin API %s: %w", adminAddr, err)
		}
		adminHTTP = &http.Server{
			Addr:              adminAddr,
			Handler:           adminSrv.Handler(),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    16 << 10,
		}
	}

	errCh := make(chan error, 2)
	go func() {
		slog.Info("Public HTTP server listening", "addr", publicLn.Addr().String())
		if err := publicHTTP.Serve(publicLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("public server failed: %w", err)
		}
	}()

	if adminHTTP != nil {
		go func() {
			slog.Info("Internal admin API server listening", "addr", adminLn.Addr().String())
			if err := adminHTTP.Serve(adminLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("admin server failed: %w", err)
			}
		}()
	} else {
		slog.Info("Internal admin API disabled (ADMIN_API_TOKEN not set)")
	}

	var runErr error
	select {
	case <-sigCtx.Done():
		slog.Info("Shutdown signal received")
	case err := <-errCh:
		runErr = err
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancelShutdown()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := publicHTTP.Shutdown(shutdownCtx); err != nil {
			slog.Error("Public server shutdown error", "err", err)
		}
	}()
	if adminHTTP != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := adminHTTP.Shutdown(shutdownCtx); err != nil {
				slog.Error("Admin server shutdown error", "err", err)
			}
		}()
	}
	wg.Wait()

	return runErr
}

func main() {
	if err := run(); err != nil {
		slog.Error("Server start failed", "error", err)
		os.Exit(1)
	}
}
