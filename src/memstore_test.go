package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

type memoryStore struct {
	mu          sync.Mutex
	settings    map[string]json.RawMessage
	users       map[uuid.UUID]UserRecord
	credsByID   map[string]CredentialRecord
	credByUser  map[uuid.UUID]string
	invites     map[uuid.UUID]InviteRecord
	challenges  map[string]ChallengeRecord
	sessions    map[uuid.UUID]SessionRecord
	saveErr     error
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		settings:   make(map[string]json.RawMessage),
		users:      make(map[uuid.UUID]UserRecord),
		credsByID:  make(map[string]CredentialRecord),
		credByUser: make(map[uuid.UUID]string),
		invites:    make(map[uuid.UUID]InviteRecord),
		challenges: make(map[string]ChallengeRecord),
		sessions:   make(map[uuid.UUID]SessionRecord),
	}
}

func (m *memoryStore) LoadSettings(_ context.Context) (map[string]json.RawMessage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]json.RawMessage, len(m.settings))
	for k, v := range m.settings {
		cp := make([]byte, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out, nil
}

func (m *memoryStore) SaveSettings(_ context.Context, settings map[string]any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveErr != nil {
		return m.saveErr
	}
	for k, v := range settings {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		m.settings[k] = json.RawMessage(b)
	}
	return nil
}

func (m *memoryStore) CreateInvite(_ context.Context, inv InviteRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv.TokenHash = append([]byte(nil), inv.TokenHash...)
	m.invites[inv.ID] = inv
	return nil
}

func (m *memoryStore) GetInviteByTokenHash(_ context.Context, tokenHash []byte) (InviteRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, inv := range m.invites {
		if subtle.ConstantTimeCompare(inv.TokenHash, tokenHash) == 1 {
			return inv, nil
		}
	}
	return InviteRecord{}, ErrNotFound
}

func (m *memoryStore) ListInvites(_ context.Context) ([]InviteRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]InviteRecord, 0, len(m.invites))
	for _, inv := range m.invites {
		out = append(out, inv)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

func (m *memoryStore) DeleteUnusedInvite(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.invites[id]
	if !ok {
		return ErrNotFound
	}
	if inv.UsedAt != nil {
		return ErrInviteAlreadyUse
	}
	delete(m.invites, id)
	for chID, ch := range m.challenges {
		if ch.InviteID != nil && *ch.InviteID == id {
			delete(m.challenges, chID)
		}
	}
	return nil
}

func (m *memoryStore) CreateChallenge(_ context.Context, ch ChallengeRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ch.SessionData = append([]byte(nil), ch.SessionData...)
	m.challenges[ch.ID] = ch
	return nil
}

func (m *memoryStore) ConsumeChallenge(_ context.Context, id, purpose string, now time.Time) (ChallengeRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ch, ok := m.challenges[id]
	if !ok || ch.Purpose != purpose || !ch.ExpiresAt.After(now) {
		return ChallengeRecord{}, ErrNotFound
	}
	delete(m.challenges, id)
	return ch, nil
}

func (m *memoryStore) CompleteInviteRegistration(_ context.Context, p CompleteInviteRegistrationParams) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.invites[p.InviteID]
	if !ok {
		return ErrInviteInvalid
	}
	if subtle.ConstantTimeCompare(inv.TokenHash, p.InviteTokenHash) != 1 || inv.UsedAt != nil || !inv.ExpiresAt.After(p.Now) {
		return ErrInviteInvalid
	}
	credKey := string(p.Credential.ID)
	if _, exists := m.credsByID[credKey]; exists {
		return ErrConflict
	}
	if _, exists := m.credByUser[p.User.ID]; exists {
		return ErrConflict
	}

	now := p.Now.UTC()
	inv.UsedAt = &now
	m.invites[inv.ID] = inv

	user := p.User
	user.DisplayName = inv.DisplayName
	user.Status = UserStatusActive
	user.CreatedAt = now
	user.LastLoginAt = &now
	m.users[user.ID] = user

	cred := p.Credential
	cred.ID = append([]byte(nil), cred.ID...)
	cred.PublicKey = append([]byte(nil), cred.PublicKey...)
	cred.Flags = append([]byte(nil), cred.Flags...)
	cred.AAGUID = append([]byte(nil), cred.AAGUID...)
	cred.Transport = append([]string(nil), cred.Transport...)
	cred.CreatedAt = now
	cred.LastUsedAt = &now
	m.credsByID[credKey] = cred
	m.credByUser[user.ID] = credKey

	sess := p.Session
	sess.TokenHash = append([]byte(nil), sess.TokenHash...)
	sess.CreatedAt = now
	sess.LastSeenAt = now
	m.sessions[sess.ID] = sess

	for chID, ch := range m.challenges {
		if ch.InviteID != nil && *ch.InviteID == inv.ID {
			delete(m.challenges, chID)
		}
	}
	return nil
}

func (m *memoryStore) GetUserAndCredentialByCredentialID(_ context.Context, credID []byte) (UserRecord, CredentialRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cred, ok := m.credsByID[string(credID)]
	if !ok {
		return UserRecord{}, CredentialRecord{}, ErrNotFound
	}
	user, ok := m.users[cred.UserID]
	if !ok {
		return UserRecord{}, CredentialRecord{}, ErrNotFound
	}
	return user, cred, nil
}

func (m *memoryStore) CompleteLogin(_ context.Context, p CompleteLoginParams) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	user, ok := m.users[p.UserID]
	if !ok {
		return ErrNotFound
	}
	if user.Status != UserStatusActive {
		return ErrUserDisabled
	}
	credKey := string(p.CredentialID)
	cred, ok := m.credsByID[credKey]
	if !ok || cred.UserID != p.UserID {
		return ErrNotFound
	}
	if !((cred.SignCount == 0 && p.SignCount == 0) || p.SignCount > cred.SignCount) {
		return ErrCloneWarning
	}

	now := p.Now.UTC()
	cred.SignCount = p.SignCount
	cred.Flags = append([]byte(nil), p.Flags...)
	cred.BackupEligible = p.BackupEligible
	cred.BackupState = p.BackupState
	cred.LastUsedAt = &now
	m.credsByID[credKey] = cred

	user.LastLoginAt = &now
	m.users[user.ID] = user

	sess := p.Session
	sess.TokenHash = append([]byte(nil), sess.TokenHash...)
	sess.CreatedAt = now
	sess.LastSeenAt = now
	m.sessions[sess.ID] = sess
	return nil
}

func (m *memoryStore) TouchSession(_ context.Context, tokenHash []byte, now time.Time, newExpiresAt time.Time) (SessionWithUser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, sess := range m.sessions {
		if bytes.Equal(sess.TokenHash, tokenHash) {
			if !sess.ExpiresAt.After(now) {
				return SessionWithUser{}, ErrNotFound
			}
			user, ok := m.users[sess.UserID]
			if !ok || user.Status != UserStatusActive {
				return SessionWithUser{}, ErrNotFound
			}
			sess.LastSeenAt = now.UTC()
			sess.ExpiresAt = newExpiresAt.UTC()
			m.sessions[id] = sess
			return SessionWithUser{Session: sess, User: user}, nil
		}
	}
	return SessionWithUser{}, ErrNotFound
}

func (m *memoryStore) DeleteSessionByTokenHash(_ context.Context, tokenHash []byte, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	wasValid := false
	for id, sess := range m.sessions {
		if bytes.Equal(sess.TokenHash, tokenHash) {
			if sess.ExpiresAt.After(now) {
				if u, ok := m.users[sess.UserID]; ok && u.Status == UserStatusActive {
					wasValid = true
				}
			}
			delete(m.sessions, id)
		}
	}
	return wasValid, nil
}

func (m *memoryStore) DeleteSessionsByUserID(_ context.Context, userID uuid.UUID) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[userID]; !ok {
		return 0, ErrNotFound
	}
	var count int64
	for id, sess := range m.sessions {
		if sess.UserID == userID {
			delete(m.sessions, id)
			count++
		}
	}
	return count, nil
}

func (m *memoryStore) ListUsers(_ context.Context, statusFilter string, now time.Time) ([]UserSummary, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]UserSummary, 0, len(m.users))
	for _, u := range m.users {
		if statusFilter != "" && u.Status != statusFilter {
			continue
		}
		activeSessions := 0
		for _, s := range m.sessions {
			if s.UserID == u.ID && s.ExpiresAt.After(now) {
				activeSessions++
			}
		}
		out = append(out, UserSummary{
			ID:             u.ID,
			DisplayName:    u.DisplayName,
			Username:       u.DisplayName,
			Status:         u.Status,
			ActiveSessions: activeSessions,
			LastLoginAt:    u.LastLoginAt,
			CreatedAt:      u.CreatedAt.UTC(),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

func (m *memoryStore) UpdateUserStatus(_ context.Context, id uuid.UUID, status string, now time.Time) (UserSummary, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return UserSummary{}, ErrNotFound
	}
	u.Status = status
	m.users[id] = u

	activeSessions := 0
	if status == UserStatusDisabled {
		for sID, s := range m.sessions {
			if s.UserID == id {
				delete(m.sessions, sID)
			}
		}
	} else {
		for _, s := range m.sessions {
			if s.UserID == id && s.ExpiresAt.After(now) {
				activeSessions++
			}
		}
	}

	return UserSummary{
		ID:             u.ID,
		DisplayName:    u.DisplayName,
		Username:       u.DisplayName,
		Status:         u.Status,
		ActiveSessions: activeSessions,
		LastLoginAt:    u.LastLoginAt,
		CreatedAt:      u.CreatedAt.UTC(),
	}, nil
}

func (m *memoryStore) DeleteUser(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[id]; !ok {
		return ErrNotFound
	}
	delete(m.users, id)
	if credKey, ok := m.credByUser[id]; ok {
		delete(m.credsByID, credKey)
		delete(m.credByUser, id)
	}
	for sID, s := range m.sessions {
		if s.UserID == id {
			delete(m.sessions, sID)
		}
	}
	return nil
}

func (m *memoryStore) CleanupExpired(_ context.Context, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, ch := range m.challenges {
		if !ch.ExpiresAt.After(now) {
			delete(m.challenges, id)
		}
	}
	for id, s := range m.sessions {
		if !s.ExpiresAt.After(now) {
			delete(m.sessions, id)
		}
	}
	return nil
}
