package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
)

const (
	DefaultListenAddr    = ":8080"
	DefaultPublicDir     = "public"
	DefaultPublicBaseURL = "http://localhost:8080"
	DefaultAdminPort     = 9090
	MinAdminTokenLen     = 16

	SessionCookieNameHTTPS = "__Host-audown_session"
	SessionCookieNameHTTP  = "audown_session"
)

// Config holds runtime configuration loaded from environment variables.
type Config struct {
	ListenAddr        string
	MainPort          int
	PublicDir         string
	PublicBaseURL     string
	RPID              string
	RPOrigin          string
	CookieSecure      bool
	SessionCookieName string
	DBBrokerURL       string
	DatabaseURL       string
	AdminPort         int
	AdminBindCIDR     *netip.Prefix
	AdminAllowCIDR    *netip.Prefix
	AdminAPIToken     string
}

// LogValue implements slog.LogValuer and redacts secret credentials.
func (c Config) LogValue() slog.Value {
	bindCIDR := ""
	if c.AdminBindCIDR != nil {
		bindCIDR = c.AdminBindCIDR.String()
	}
	allowCIDR := ""
	if c.AdminAllowCIDR != nil {
		allowCIDR = c.AdminAllowCIDR.String()
	}
	return slog.GroupValue(
		slog.String("listen_addr", c.ListenAddr),
		slog.Int("main_port", c.MainPort),
		slog.String("public_dir", c.PublicDir),
		slog.String("public_base_url", c.PublicBaseURL),
		slog.String("rp_id", c.RPID),
		slog.Bool("cookie_secure", c.CookieSecure),
		slog.Bool("db_broker_configured", c.DBBrokerURL != ""),
		slog.Bool("database_url_configured", c.DatabaseURL != ""),
		slog.String("database_url", "[redacted]"),
		slog.Int("admin_port", c.AdminPort),
		slog.Bool("admin_api_enabled", c.AdminAPIToken != ""),
		slog.String("admin_bind_cidr", bindCIDR),
		slog.String("admin_allow_cidr", allowCIDR),
		slog.String("admin_api_token", "[redacted]"),
	)
}

// String implements fmt.Stringer without exposing secrets.
func (c Config) String() string {
	return fmt.Sprintf("Config{ListenAddr:%q PublicBaseURL:%q RPID:%q AdminPort:%d AdminAPIEnabled:%t DBBroker:%t}",
		c.ListenAddr, c.PublicBaseURL, c.RPID, c.AdminPort, c.AdminAPIToken != "", c.DBBrokerURL != "")
}

// LoadConfigFromEnv reads configuration from the process environment.
func LoadConfigFromEnv() (Config, error) {
	return LoadConfig(os.Getenv)
}

// LoadConfig reads and validates runtime configuration from getenv.
func LoadConfig(getenv func(string) string) (Config, error) {
	listenAddr := envOrDefault(getenv, "LISTEN_ADDR", DefaultListenAddr)
	_, portStr, err := net.SplitHostPort(listenAddr)
	if err != nil || portStr == "" {
		return Config{}, fmt.Errorf("invalid LISTEN_ADDR %q: expected host:port", listenAddr)
	}
	mainPort, err := strconv.Atoi(portStr)
	if err != nil || mainPort < 1 || mainPort > 65535 {
		return Config{}, fmt.Errorf("invalid LISTEN_ADDR port %q: must be 1..65535", portStr)
	}

	publicDirRaw := envOrDefault(getenv, "PUBLIC_DIR_NAME", DefaultPublicDir)
	publicDirPath, err := filepath.Abs(publicDirRaw)
	if err != nil {
		return Config{}, fmt.Errorf("resolve PUBLIC_DIR_NAME: %w", err)
	}

	publicBaseRaw := envOrDefault(getenv, "PUBLIC_BASE_URL", DefaultPublicBaseURL)
	publicBaseURL, rpID, cookieSecure, err := ParsePublicBaseURL(publicBaseRaw)
	if err != nil {
		return Config{}, err
	}
	sessionCookieName := SessionCookieNameHTTP
	if cookieSecure {
		sessionCookieName = SessionCookieNameHTTPS
	}

	dbBrokerURL := strings.TrimSpace(getenv("DB_BROKER_URL"))
	if dbBrokerURL != "" {
		u, err := url.Parse(dbBrokerURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return Config{}, errors.New("invalid DB_BROKER_URL: expected http:// or https:// URL")
		}
	}

	cfg := Config{
		ListenAddr:        listenAddr,
		MainPort:          mainPort,
		PublicDir:         publicDirPath,
		PublicBaseURL:     publicBaseURL,
		RPID:              rpID,
		RPOrigin:          publicBaseURL,
		CookieSecure:      cookieSecure,
		SessionCookieName: sessionCookieName,
		DBBrokerURL:       dbBrokerURL,
		DatabaseURL:       strings.TrimSpace(getenv("DATABASE_URL")),
		AdminPort:         DefaultAdminPort,
		AdminAPIToken:     strings.TrimSpace(getenv("ADMIN_API_TOKEN")),
	}

	rawAdminPort := strings.TrimSpace(getenv("ADMIN_PORT"))
	if rawAdminPort != "" {
		p, err := strconv.Atoi(rawAdminPort)
		if err != nil || p < 1 || p > 65535 {
			return Config{}, fmt.Errorf("invalid ADMIN_PORT %q: must be 1..65535", rawAdminPort)
		}
		cfg.AdminPort = p
	}

	if rawCIDR := strings.TrimSpace(getenv("ADMIN_BIND_CIDR")); rawCIDR != "" {
		pfx, err := parseAdminCIDR("ADMIN_BIND_CIDR", rawCIDR)
		if err != nil {
			return Config{}, err
		}
		cfg.AdminBindCIDR = &pfx
	}

	if rawAllow := strings.TrimSpace(getenv("ADMIN_ALLOW_CIDR")); rawAllow != "" {
		pfx, err := parseAdminCIDR("ADMIN_ALLOW_CIDR", rawAllow)
		if err != nil {
			return Config{}, err
		}
		if cfg.AdminBindCIDR == nil && !pfx.Contains(netip.MustParseAddr("127.0.0.1")) {
			return Config{}, fmt.Errorf("ADMIN_ALLOW_CIDR %s cannot reach loopback 127.0.0.1 while ADMIN_BIND_CIDR is unset", pfx.String())
		}
		cfg.AdminAllowCIDR = &pfx
	} else if cfg.AdminBindCIDR != nil {
		pfx := *cfg.AdminBindCIDR
		cfg.AdminAllowCIDR = &pfx
	}

	if cfg.AdminAPIToken != "" {
		if err := ValidateAdminToken(cfg.AdminAPIToken); err != nil {
			return Config{}, err
		}
	}

	if cfg.AdminPort == cfg.MainPort && (cfg.AdminAPIToken != "" || rawAdminPort != "") {
		return Config{}, fmt.Errorf("ADMIN_PORT (%d) must differ from main HTTP port (%d)", cfg.AdminPort, cfg.MainPort)
	}

	return cfg, nil
}

// ParsePublicBaseURL validates and normalizes PUBLIC_BASE_URL into canonical origin,
// WebAuthn RPID (hostname), and HTTPS secure flag.
func ParsePublicBaseURL(raw string) (origin string, rpID string, isHTTPS bool, err error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", false, fmt.Errorf("invalid PUBLIC_BASE_URL %q: %w", raw, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", "", false, fmt.Errorf("invalid PUBLIC_BASE_URL %q: scheme must be http or https", raw)
	}
	if u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawFragment != "" {
		return "", "", false, fmt.Errorf("invalid PUBLIC_BASE_URL %q: must not include userinfo, query, or fragment", raw)
	}
	if u.Path != "" && u.Path != "/" {
		return "", "", false, fmt.Errorf("invalid PUBLIC_BASE_URL %q: must not include a subpath", raw)
	}
	hostname := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if hostname == "" {
		return "", "", false, fmt.Errorf("invalid PUBLIC_BASE_URL %q: missing host", raw)
	}
	if _, ipErr := netip.ParseAddr(hostname); ipErr == nil {
		return "", "", false, fmt.Errorf("invalid PUBLIC_BASE_URL %q: WebAuthn RPID cannot be an IP address (use a hostname such as localhost or audown.cubus.sh)", raw)
	}
	port := u.Port()
	if port != "" {
		p, pErr := strconv.Atoi(port)
		if pErr != nil || p < 1 || p > 65535 {
			return "", "", false, fmt.Errorf("invalid PUBLIC_BASE_URL %q: invalid port", raw)
		}
	}

	// Normalize default ports so Origin header matching works strictly.
	host := hostname
	if strings.Contains(hostname, ":") {
		host = "[" + hostname + "]"
	}
	if port != "" && !((scheme == "https" && port == "443") || (scheme == "http" && port == "80")) {
		host = net.JoinHostPort(hostname, port)
	}

	return scheme + "://" + host, hostname, scheme == "https", nil
}

// ValidatePublicDir ensures the static web root exists and is a directory.
func ValidatePublicDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("public directory %q unavailable: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("public directory %q is not a directory", dir)
	}
	return nil
}

func parseAdminCIDR(name, raw string) (netip.Prefix, error) {
	pfx, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid %s %q: %w", name, raw, err)
	}
	if pfx.Bits() == 0 {
		return netip.Prefix{}, fmt.Errorf("%s %q must not be a catch-all /0 prefix", name, raw)
	}
	if pfx.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("%s %q must use canonical IPv4 or IPv6 CIDR notation", name, raw)
	}
	return pfx.Masked(), nil
}

// ValidateAdminToken ensures an enabled Admin API token meets length and non-placeholder rules.
func ValidateAdminToken(token string) error {
	if token == "" {
		return errors.New("ADMIN_API_TOKEN must not be empty")
	}
	if IsPlaceholder(token) {
		return errors.New("ADMIN_API_TOKEN must not be a placeholder")
	}
	if len(token) < MinAdminTokenLen {
		return fmt.Errorf("ADMIN_API_TOKEN must be at least %d bytes", MinAdminTokenLen)
	}
	if strings.IndexFunc(token, unicode.IsSpace) != -1 {
		return errors.New("ADMIN_API_TOKEN must not contain whitespace")
	}
	return nil
}

// IsPlaceholder reports whether v looks like an unedited template placeholder value.
func IsPlaceholder(v string) bool {
	low := strings.ToLower(strings.TrimSpace(v))
	return strings.HasPrefix(low, "replace-with-") || low == "changeme" || low == "change-me"
}

// ResolveBindAddr resolves the exact interface listen address for the Admin API.
// It never returns 0.0.0.0 or ::; it binds either the matching local interface IP
// inside bindCIDR or 127.0.0.1 when bindCIDR is nil.
func ResolveBindAddr(bindCIDR *netip.Prefix, port int) (string, error) {
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid admin port %d: must be 1..65535", port)
	}
	if bindCIDR == nil {
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), nil
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", fmt.Errorf("list interface addresses: %w", err)
	}
	return resolveBindAddrFrom(addrs, bindCIDR, port)
}

func resolveBindAddrFrom(addrs []net.Addr, bindCIDR *netip.Prefix, port int) (string, error) {
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid admin port %d: must be 1..65535", port)
	}
	if bindCIDR == nil {
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), nil
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		addr, ok := netip.AddrFromSlice(ipNet.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if !addr.IsValid() || addr.IsUnspecified() {
			continue
		}
		if bindCIDR.Contains(addr) {
			return net.JoinHostPort(addr.String(), strconv.Itoa(port)), nil
		}
	}
	return "", fmt.Errorf("no local interface IP found inside ADMIN_BIND_CIDR %s", bindCIDR.String())
}

func envOrDefault(getenv func(string) string, key, fallback string) string {
	if v := strings.TrimSpace(getenv(key)); v != "" {
		return v
	}
	return fallback
}
