package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	UserStatusActive   = "active"
	UserStatusDisabled = "disabled"

	ChallengePurposeRegister = "register"
	ChallengePurposeLogin    = "login"

	InviteStatusPending = "pending"
	InviteStatusUsed    = "used"
	InviteStatusExpired = "expired"
)

var (
	ErrNotFound         = errors.New("not found")
	ErrInviteInvalid    = errors.New("invite invalid, expired, or already used")
	ErrInviteAlreadyUse = errors.New("invite already used")
	ErrUserDisabled     = errors.New("user disabled")
	ErrCloneWarning     = errors.New("possible cloned authenticator")
	ErrConflict         = errors.New("conflict")
)

type UserRecord struct {
	ID          uuid.UUID  `json:"id"`
	DisplayName string     `json:"display_name"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at"`
}

// UserSummary is the Admin API user representation.
type UserSummary struct {
	ID             uuid.UUID  `json:"id"`
	DisplayName    string     `json:"display_name"`
	Username       string     `json:"username"`
	Status         string     `json:"status"`
	ActiveSessions int        `json:"active_sessions"`
	LastLoginAt    *time.Time `json:"last_login_at"`
	CreatedAt      time.Time  `json:"created_at"`
}

type CredentialRecord struct {
	ID              []byte
	UserID          uuid.UUID
	PublicKey       []byte
	AttestationType string
	Transport       []string
	Flags           []byte
	AAGUID          []byte
	SignCount       uint32
	BackupEligible  bool
	BackupState     bool
	CreatedAt       time.Time
	LastUsedAt      *time.Time
}

type ChallengeRecord struct {
	ID          string
	Purpose     string
	InviteID    *uuid.UUID
	SessionData []byte
	ExpiresAt   time.Time
}

type InviteRecord struct {
	ID          uuid.UUID
	TokenHash   []byte
	DisplayName string
	ExpiresAt   time.Time
	UsedAt      *time.Time
	CreatedBy   string
	CreatedAt   time.Time
}

// InviteView is the safe Admin API invite representation (never exposes token or hash).
type InviteView struct {
	ID          uuid.UUID  `json:"id"`
	DisplayName string     `json:"display_name"`
	Status      string     `json:"status"`
	ExpiresAt   time.Time  `json:"expires_at"`
	UsedAt      *time.Time `json:"used_at"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
}

func (inv InviteRecord) View(now time.Time) InviteView {
	status := InviteStatusPending
	if inv.UsedAt != nil {
		status = InviteStatusUsed
	} else if !inv.ExpiresAt.After(now) {
		status = InviteStatusExpired
	}
	return InviteView{
		ID:          inv.ID,
		DisplayName: inv.DisplayName,
		Status:      status,
		ExpiresAt:   inv.ExpiresAt.UTC(),
		UsedAt:      inv.UsedAt,
		CreatedBy:   inv.CreatedBy,
		CreatedAt:   inv.CreatedAt.UTC(),
	}
}

type SessionRecord struct {
	ID         uuid.UUID
	TokenHash  []byte
	UserID     uuid.UUID
	UserAgent  string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
}

type SessionWithUser struct {
	Session SessionRecord
	User    UserRecord
}

type CompleteInviteRegistrationParams struct {
	InviteID        uuid.UUID
	InviteTokenHash []byte
	User            UserRecord
	Credential      CredentialRecord
	Session         SessionRecord
	Now             time.Time
}

type CompleteLoginParams struct {
	UserID         uuid.UUID
	CredentialID   []byte
	Flags          []byte
	SignCount      uint32
	BackupEligible bool
	BackupState    bool
	Session        SessionRecord
	Now            time.Time
}

// Store abstracts PostgreSQL persistence so tests can run fast in-memory.
type Store interface {
	// Settings
	LoadSettings(ctx context.Context) (map[string]json.RawMessage, error)
	SaveSettings(ctx context.Context, settings map[string]any) error

	// Invites
	CreateInvite(ctx context.Context, inv InviteRecord) error
	GetInviteByTokenHash(ctx context.Context, tokenHash []byte) (InviteRecord, error)
	ListInvites(ctx context.Context) ([]InviteRecord, error)
	DeleteUnusedInvite(ctx context.Context, id uuid.UUID) error

	// Challenges (single-use atomic consume)
	CreateChallenge(ctx context.Context, ch ChallengeRecord) error
	ConsumeChallenge(ctx context.Context, id, purpose string, now time.Time) (ChallengeRecord, error)

	// Registration & Login atomic flows
	CompleteInviteRegistration(ctx context.Context, p CompleteInviteRegistrationParams) error
	GetUserAndCredentialByCredentialID(ctx context.Context, credID []byte) (UserRecord, CredentialRecord, error)
	CompleteLogin(ctx context.Context, p CompleteLoginParams) error

	// Sessions
	TouchSession(ctx context.Context, tokenHash []byte, now time.Time, newExpiresAt time.Time) (SessionWithUser, error)
	DeleteSessionByTokenHash(ctx context.Context, tokenHash []byte, now time.Time) (bool, error)
	DeleteSessionsByUserID(ctx context.Context, userID uuid.UUID) (int64, error)

	// Users (Admin API)
	ListUsers(ctx context.Context, statusFilter string, now time.Time) ([]UserSummary, error)
	UpdateUserStatus(ctx context.Context, id uuid.UUID, status string, now time.Time) (UserSummary, error)
	DeleteUser(ctx context.Context, id uuid.UUID) error

	// Maintenance
	CleanupExpired(ctx context.Context, now time.Time) error
}

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func (s *PostgresStore) LoadSettings(ctx context.Context) (map[string]json.RawMessage, error) {
	rows, err := s.pool.Query(ctx, `SELECT key, value FROM app_settings`)
	if err != nil {
		return nil, fmt.Errorf("query app_settings: %w", err)
	}
	defer rows.Close()

	out := make(map[string]json.RawMessage)
	for rows.Next() {
		var k string
		var raw []byte
		if err := rows.Scan(&k, &raw); err != nil {
			return nil, fmt.Errorf("scan app_settings: %w", err)
		}
		cp := make([]byte, len(raw))
		copy(cp, raw)
		out[k] = json.RawMessage(cp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate app_settings: %w", err)
	}
	return out, nil
}

func (s *PostgresStore) SaveSettings(ctx context.Context, settings map[string]any) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin save settings tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for k, v := range settings {
		encoded, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("marshal setting %s: %w", k, err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO app_settings (key, value, updated_at)
			VALUES ($1, $2::jsonb, now())
			ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
		`, k, string(encoded)); err != nil {
			return fmt.Errorf("upsert setting %s: %w", k, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit save settings: %w", err)
	}
	return nil
}

func (s *PostgresStore) CreateInvite(ctx context.Context, inv InviteRecord) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO invite_tokens (id, token_hash, display_name, expires_at, used_at, created_by, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, inv.ID, inv.TokenHash, inv.DisplayName, inv.ExpiresAt.UTC(), inv.UsedAt, inv.CreatedBy, inv.CreatedAt.UTC())
	if err != nil {
		return fmt.Errorf("insert invite: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetInviteByTokenHash(ctx context.Context, tokenHash []byte) (InviteRecord, error) {
	var inv InviteRecord
	err := s.pool.QueryRow(ctx, `
		SELECT id, token_hash, display_name, expires_at, used_at, created_by, created_at
		FROM invite_tokens
		WHERE token_hash = $1
	`, tokenHash).Scan(
		&inv.ID, &inv.TokenHash, &inv.DisplayName, &inv.ExpiresAt, &inv.UsedAt, &inv.CreatedBy, &inv.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return InviteRecord{}, ErrNotFound
	}
	if err != nil {
		return InviteRecord{}, fmt.Errorf("get invite by token hash: %w", err)
	}
	return inv, nil
}

func (s *PostgresStore) ListInvites(ctx context.Context) ([]InviteRecord, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, token_hash, display_name, expires_at, used_at, created_by, created_at
		FROM invite_tokens
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("list invites: %w", err)
	}
	defer rows.Close()

	out := make([]InviteRecord, 0)
	for rows.Next() {
		var inv InviteRecord
		if err := rows.Scan(
			&inv.ID, &inv.TokenHash, &inv.DisplayName, &inv.ExpiresAt, &inv.UsedAt, &inv.CreatedBy, &inv.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan invite: %w", err)
		}
		out = append(out, inv)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate invites: %w", err)
	}
	return out, nil
}

func (s *PostgresStore) DeleteUnusedInvite(ctx context.Context, id uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin delete invite tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var usedAt *time.Time
	err = tx.QueryRow(ctx, `SELECT used_at FROM invite_tokens WHERE id = $1 FOR UPDATE`, id).Scan(&usedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("lock invite: %w", err)
	}
	if usedAt != nil {
		return ErrInviteAlreadyUse
	}
	if _, err := tx.Exec(ctx, `DELETE FROM invite_tokens WHERE id = $1`, id); err != nil {
		return fmt.Errorf("delete invite: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit delete invite: %w", err)
	}
	return nil
}

func (s *PostgresStore) CreateChallenge(ctx context.Context, ch ChallengeRecord) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO webauthn_challenges (id, purpose, invite_id, session_data, expires_at)
		VALUES ($1, $2, $3, $4::jsonb, $5)
	`, ch.ID, ch.Purpose, ch.InviteID, string(ch.SessionData), ch.ExpiresAt.UTC())
	if err != nil {
		return fmt.Errorf("insert challenge: %w", err)
	}
	return nil
}

func (s *PostgresStore) ConsumeChallenge(ctx context.Context, id, purpose string, now time.Time) (ChallengeRecord, error) {
	var ch ChallengeRecord
	var rawData []byte
	err := s.pool.QueryRow(ctx, `
		DELETE FROM webauthn_challenges
		WHERE id = $1 AND purpose = $2 AND expires_at > $3
		RETURNING id, purpose, invite_id, session_data, expires_at
	`, id, purpose, now.UTC()).Scan(&ch.ID, &ch.Purpose, &ch.InviteID, &rawData, &ch.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ChallengeRecord{}, ErrNotFound
	}
	if err != nil {
		return ChallengeRecord{}, fmt.Errorf("consume challenge: %w", err)
	}
	ch.SessionData = rawData
	return ch, nil
}

func (s *PostgresStore) CompleteInviteRegistration(ctx context.Context, p CompleteInviteRegistrationParams) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin registration tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var (
		tokenHash   []byte
		displayName string
		expiresAt   time.Time
		usedAt      *time.Time
	)
	err = tx.QueryRow(ctx, `
		SELECT token_hash, display_name, expires_at, used_at
		FROM invite_tokens
		WHERE id = $1
		FOR UPDATE
	`, p.InviteID).Scan(&tokenHash, &displayName, &expiresAt, &usedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInviteInvalid
	}
	if err != nil {
		return fmt.Errorf("lock invite for registration: %w", err)
	}
	if subtle.ConstantTimeCompare(tokenHash, p.InviteTokenHash) != 1 || usedAt != nil || !expiresAt.After(p.Now) {
		return ErrInviteInvalid
	}

	now := p.Now.UTC()
	if _, err := tx.Exec(ctx, `UPDATE invite_tokens SET used_at = $2 WHERE id = $1`, p.InviteID, now); err != nil {
		return fmt.Errorf("mark invite used: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO users (id, display_name, status, created_at, last_login_at)
		VALUES ($1, $2, $3, $4, $5)
	`, p.User.ID, displayName, UserStatusActive, now, now); err != nil {
		return fmt.Errorf("insert user: %w", err)
	}

	transports := p.Credential.Transport
	if transports == nil {
		transports = []string{}
	}
	flags := p.Credential.Flags
	if len(flags) == 0 {
		flags = []byte{0}
	}
	aaguid := p.Credential.AAGUID
	if aaguid == nil {
		aaguid = []byte{}
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO webauthn_credentials (
			id, user_id, public_key, attestation_type, transport,
			flags, aaguid, sign_count, backup_eligible, backup_state,
			created_at, last_used_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11)
	`,
		p.Credential.ID, p.User.ID, p.Credential.PublicKey, p.Credential.AttestationType, transports,
		flags, aaguid, int64(p.Credential.SignCount), p.Credential.BackupEligible, p.Credential.BackupState,
		now,
	); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrConflict
		}
		return fmt.Errorf("insert webauthn credential: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO sessions (id, token_hash, user_id, user_agent, created_at, last_seen_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`,
		p.Session.ID, p.Session.TokenHash, p.User.ID, p.Session.UserAgent,
		now, now, p.Session.ExpiresAt.UTC(),
	); err != nil {
		return fmt.Errorf("insert initial session: %w", err)
	}

	// Clean up any other pending register challenges tied to this invite.
	if _, err := tx.Exec(ctx, `DELETE FROM webauthn_challenges WHERE invite_id = $1`, p.InviteID); err != nil {
		return fmt.Errorf("cleanup invite challenges: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit registration tx: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetUserAndCredentialByCredentialID(ctx context.Context, credID []byte) (UserRecord, CredentialRecord, error) {
	var u UserRecord
	var c CredentialRecord
	var signCount int64
	err := s.pool.QueryRow(ctx, `
		SELECT
			u.id, u.display_name, u.status, u.created_at, u.last_login_at,
			c.id, c.user_id, c.public_key, c.attestation_type, c.transport,
			c.flags, c.aaguid, c.sign_count, c.backup_eligible, c.backup_state,
			c.created_at, c.last_used_at
		FROM webauthn_credentials c
		JOIN users u ON u.id = c.user_id
		WHERE c.id = $1
	`, credID).Scan(
		&u.ID, &u.DisplayName, &u.Status, &u.CreatedAt, &u.LastLoginAt,
		&c.ID, &c.UserID, &c.PublicKey, &c.AttestationType, &c.Transport,
		&c.Flags, &c.AAGUID, &signCount, &c.BackupEligible, &c.BackupState,
		&c.CreatedAt, &c.LastUsedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return UserRecord{}, CredentialRecord{}, ErrNotFound
	}
	if err != nil {
		return UserRecord{}, CredentialRecord{}, fmt.Errorf("lookup credential: %w", err)
	}
	if signCount < 0 {
		signCount = 0
	}
	c.SignCount = uint32(signCount)
	return u, c, nil
}

func (s *PostgresStore) CompleteLogin(ctx context.Context, p CompleteLoginParams) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin login tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var status string
	err = tx.QueryRow(ctx, `SELECT status FROM users WHERE id = $1 FOR UPDATE`, p.UserID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("lock user for login: %w", err)
	}
	if status != UserStatusActive {
		return ErrUserDisabled
	}

	var currentSignCount int64
	err = tx.QueryRow(ctx, `
		SELECT sign_count
		FROM webauthn_credentials
		WHERE id = $1 AND user_id = $2
		FOR UPDATE
	`, p.CredentialID, p.UserID).Scan(&currentSignCount)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("lock credential for login: %w", err)
	}
	if !((currentSignCount == 0 && p.SignCount == 0) || int64(p.SignCount) > currentSignCount) {
		return ErrCloneWarning
	}

	now := p.Now.UTC()
	flags := p.Flags
	if len(flags) == 0 {
		flags = []byte{0}
	}

	tag, err := tx.Exec(ctx, `
		UPDATE webauthn_credentials
		SET sign_count = $2,
			flags = $3,
			backup_eligible = $4,
			backup_state = $5,
			last_used_at = $6
		WHERE id = $1 AND user_id = $7
	`, p.CredentialID, int64(p.SignCount), flags, p.BackupEligible, p.BackupState, now, p.UserID)
	if err != nil {
		return fmt.Errorf("update credential counter: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}

	if _, err := tx.Exec(ctx, `UPDATE users SET last_login_at = $2 WHERE id = $1`, p.UserID, now); err != nil {
		return fmt.Errorf("update user last_login_at: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO sessions (id, token_hash, user_id, user_agent, created_at, last_seen_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`,
		p.Session.ID, p.Session.TokenHash, p.UserID, p.Session.UserAgent,
		now, now, p.Session.ExpiresAt.UTC(),
	); err != nil {
		return fmt.Errorf("insert session: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit login tx: %w", err)
	}
	return nil
}

func (s *PostgresStore) TouchSession(ctx context.Context, tokenHash []byte, now time.Time, newExpiresAt time.Time) (SessionWithUser, error) {
	var out SessionWithUser
	nowUTC := now.UTC()
	expUTC := newExpiresAt.UTC()
	err := s.pool.QueryRow(ctx, `
		UPDATE sessions s
		SET last_seen_at = $2, expires_at = $3
		FROM users u
		WHERE s.token_hash = $1
			AND s.expires_at > $2
			AND u.id = s.user_id
			AND u.status = 'active'
		RETURNING s.id, s.token_hash, s.user_id, s.user_agent, s.created_at, s.last_seen_at, s.expires_at,
			u.display_name, u.status, u.created_at, u.last_login_at
	`, tokenHash, nowUTC, expUTC).Scan(
		&out.Session.ID, &out.Session.TokenHash, &out.Session.UserID, &out.Session.UserAgent,
		&out.Session.CreatedAt, &out.Session.LastSeenAt, &out.Session.ExpiresAt,
		&out.User.DisplayName, &out.User.Status, &out.User.CreatedAt, &out.User.LastLoginAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return SessionWithUser{}, ErrNotFound
	}
	if err != nil {
		return SessionWithUser{}, fmt.Errorf("touch session: %w", err)
	}
	out.User.ID = out.Session.UserID
	return out, nil
}

func (s *PostgresStore) DeleteSessionByTokenHash(ctx context.Context, tokenHash []byte, now time.Time) (bool, error) {
	var wasValid bool
	err := s.pool.QueryRow(ctx, `
		DELETE FROM sessions s
		USING users u
		WHERE s.token_hash = $1 AND u.id = s.user_id
		RETURNING (s.expires_at > $2 AND u.status = 'active')
	`, tokenHash, now.UTC()).Scan(&wasValid)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("delete session: %w", err)
	}
	return wasValid, nil
}

func (s *PostgresStore) DeleteSessionsByUserID(ctx context.Context, userID uuid.UUID) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin revoke sessions tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)`, userID).Scan(&exists); err != nil {
		return 0, fmt.Errorf("check user exists: %w", err)
	}
	if !exists {
		return 0, ErrNotFound
	}

	tag, err := tx.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID)
	if err != nil {
		return 0, fmt.Errorf("delete user sessions: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit revoke sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

func (s *PostgresStore) ListUsers(ctx context.Context, statusFilter string, now time.Time) ([]UserSummary, error) {
	nowUTC := now.UTC()
	var (
		rows pgx.Rows
		err  error
	)
	if statusFilter != "" {
		rows, err = s.pool.Query(ctx, `
			SELECT u.id, u.display_name, u.status, u.last_login_at, u.created_at,
				COUNT(s.id) FILTER (WHERE s.expires_at > $1) AS active_sessions
			FROM users u
			LEFT JOIN sessions s ON s.user_id = u.id
			WHERE u.status = $2
			GROUP BY u.id
			ORDER BY u.created_at DESC
		`, nowUTC, statusFilter)
	} else {
		rows, err = s.pool.Query(ctx, `
			SELECT u.id, u.display_name, u.status, u.last_login_at, u.created_at,
				COUNT(s.id) FILTER (WHERE s.expires_at > $1) AS active_sessions
			FROM users u
			LEFT JOIN sessions s ON s.user_id = u.id
			GROUP BY u.id
			ORDER BY u.created_at DESC
		`, nowUTC)
	}
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	out := make([]UserSummary, 0)
	for rows.Next() {
		var u UserSummary
		if err := rows.Scan(&u.ID, &u.DisplayName, &u.Status, &u.LastLoginAt, &u.CreatedAt, &u.ActiveSessions); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		u.Username = u.DisplayName
		u.CreatedAt = u.CreatedAt.UTC()
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate users: %w", err)
	}
	return out, nil
}

func (s *PostgresStore) UpdateUserStatus(ctx context.Context, id uuid.UUID, status string, now time.Time) (UserSummary, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return UserSummary{}, fmt.Errorf("begin update user status tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var u UserSummary
	err = tx.QueryRow(ctx, `
		UPDATE users
		SET status = $2
		WHERE id = $1
		RETURNING id, display_name, status, last_login_at, created_at
	`, id, status).Scan(&u.ID, &u.DisplayName, &u.Status, &u.LastLoginAt, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return UserSummary{}, ErrNotFound
	}
	if err != nil {
		return UserSummary{}, fmt.Errorf("update user status: %w", err)
	}

	if status == UserStatusDisabled {
		if _, err := tx.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, id); err != nil {
			return UserSummary{}, fmt.Errorf("delete disabled user sessions: %w", err)
		}
		u.ActiveSessions = 0
	} else {
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM sessions WHERE user_id = $1 AND expires_at > $2`, id, now.UTC()).Scan(&u.ActiveSessions); err != nil {
			return UserSummary{}, fmt.Errorf("count active sessions: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return UserSummary{}, fmt.Errorf("commit update user status: %w", err)
	}
	u.Username = u.DisplayName
	u.CreatedAt = u.CreatedAt.UTC()
	return u, nil
}

func (s *PostgresStore) DeleteUser(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) CleanupExpired(ctx context.Context, now time.Time) error {
	nowUTC := now.UTC()
	if _, err := s.pool.Exec(ctx, `DELETE FROM webauthn_challenges WHERE expires_at <= $1`, nowUTC); err != nil {
		return fmt.Errorf("cleanup challenges: %w", err)
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at <= $1`, nowUTC); err != nil {
		return fmt.Errorf("cleanup sessions: %w", err)
	}
	return nil
}
