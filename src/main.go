package main

import (
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

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

const urlFormat01 = "https://www.youtube.com/"
const urlFormat02 = "https://youtu.be/"

func isUrlFormatRight(url string) bool {
	return strings.HasPrefix(url, urlFormat01) ||
		strings.HasPrefix(url, urlFormat02)
}

var timeNotification = regexp.MustCompile(`^\d{2}:[0-5]\d:[0-5]\d$`)

func isTimeExpressionRight(startTime string, endTime string) bool {
	return (startTime == "" || timeNotification.MatchString(startTime)) &&
		(endTime == "" || timeNotification.MatchString(endTime))
}

const badRequestMsg = "잘못된 입력입니다. 다시 시도해주세요."
const internalServerErrorMsg = "오류가 발생했습니다. 다시 시도해주세요."

func main() {
	slog.Info("Server start")

	badRequestQuery := "/?err=" + url.QueryEscape(badRequestMsg)
	internalServerErrorQuery := "/?err=" + url.QueryEscape(internalServerErrorMsg)

	publicDir := os.Getenv("PUBLIC_DIR_NAME")
	publicDirPath, publicDirErr := filepath.Abs(publicDir)
	if publicDirErr != nil {
		slog.Error("Server start failed", "error", publicDirErr)
		return
	}

	http.Handle("/", http.FileServer(http.Dir(publicDirPath)))
	http.HandleFunc("POST /download", func(w http.ResponseWriter, r *http.Request) {
		if parseErr := r.ParseForm(); parseErr != nil {
			slog.Error("Bad Request", "error", parseErr)
			http.Redirect(w, r, badRequestQuery, http.StatusSeeOther)
			return
		}

		url := r.PostForm.Get("url")
		if url == "" {
			slog.Error("Bad Request", "error", "empty url field")
			http.Redirect(w, r, badRequestQuery, http.StatusSeeOther)
			return
		}
		if !isUrlFormatRight(url) {
			slog.Error("Bad Request", "error", "invalid url format", "url", url)
			http.Redirect(w, r, badRequestQuery, http.StatusSeeOther)
			return
		}
		
		startTime := r.PostForm.Get("startTime")
		endTime := r.PostForm.Get("endTime")
		if !isTimeExpressionRight(startTime, endTime) {
			slog.Error("Server Error", "error", "time expression is wrong", "startTime", startTime, "endTime", endTime)
			http.Redirect(w, r, internalServerErrorQuery, http.StatusSeeOther)
			return
		}

		tempDirPath, tempDirErr := os.MkdirTemp("", "download-")
		if tempDirErr != nil {
			slog.Error("Server Error", "error", tempDirErr)
			http.Redirect(w, r, internalServerErrorQuery, http.StatusSeeOther)
			return
		}

		defer os.RemoveAll(tempDirPath)

		musicDownloadPath := filepath.Join(tempDirPath, "%(title)s.%(ext)s")
		process := "uv"
		args := []string{
			"run",
			"--with=yt-dlp",
			"yt-dlp",
			"-o",
			musicDownloadPath,
			"-x",
			"--audio-format=mp3",
			"--no-continue",
			"--ignore-errors",
			"--no-playlist",
		}

		if !(startTime == "" && endTime == "") {
			args = append(args, "--download-sections", "*"+startTime+"-"+endTime)
		}

		args = append(args, url)

		cmd := exec.Command(process, args...)
		cmdErr := cmd.Run()
		if cmdErr != nil {
			slog.Error("Server Error", "error", cmdErr)
			http.Redirect(w, r, internalServerErrorQuery, http.StatusSeeOther)
			return
		}

		files, musicCheckErr := os.ReadDir(tempDirPath)
		if musicCheckErr != nil || len(files) != 1 {
			slog.Error("Server Error", "error", cmdErr)
			http.Redirect(w, r, internalServerErrorQuery, http.StatusSeeOther)
			return
		}

		musicName := files[0].Name()
		musicPath := filepath.Join(tempDirPath, musicName)
		w.Header().Set("Content-Disposition", mime.FormatMediaType(
			"attachment",
			map[string]string{"filename": musicName},
		))
		w.Header().Set("Content-Type", mime.TypeByExtension("mp3"))

		slog.Info("Music Download", "musicName", musicName)
		http.ServeFile(w, r, musicPath)
	})

	if httpErr := http.ListenAndServe(":80", logging(http.DefaultServeMux)); httpErr != nil {
		slog.Error("Server start failed", "error", httpErr)
		return
	}
}
