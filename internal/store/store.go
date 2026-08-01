package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type User struct {
	ID          string `json:"id"`
	Subject     string `json:"subject"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	AvatarURL   string `json:"avatarUrl,omitempty"`
	CreatedAt   int64  `json:"createdAt"`
}

type RefreshToken struct {
	Hash      string `json:"hash"`
	UserID    string `json:"userId"`
	DeviceID  string `json:"deviceId"`
	ExpiresAt int64  `json:"expiresAt"`
}

type DeviceInfo struct {
	CPULabel   string  `json:"cpuLabel,omitempty"`
	MemoryGB   float64 `json:"memoryGb,omitempty"`
	OSVersion  string  `json:"osVersion,omitempty"`
	ModelLabel string  `json:"modelLabel,omitempty"`
}

type Device struct {
	DeviceID             string      `json:"deviceId"`
	UserID               string      `json:"userId"`
	Name                 string      `json:"name"`
	ManualName           *string     `json:"manualName,omitempty"`
	Platform             string      `json:"platform"`
	AppVersion           string      `json:"appVersion"`
	LastSeenAt           int64       `json:"lastSeenAt"`
	RemoteControlEnabled bool        `json:"remoteControlEnabled"`
	Busy                 bool        `json:"busy"`
	Info                 *DeviceInfo `json:"deviceInfo,omitempty"`
}

type PushToken struct {
	Token      string `json:"token"`
	UserID     string `json:"userId"`
	DeviceID   string `json:"deviceId"`
	Provider   string `json:"provider"`
	Platform   string `json:"platform"`
	AppVariant string `json:"appVariant"`
	APNSEnv    string `json:"apnsEnv"`
}

type snapshot struct {
	Users         map[string]User         `json:"users"`
	RefreshTokens map[string]RefreshToken `json:"refreshTokens"`
	Devices       map[string]Device       `json:"devices"`
	PushTokens    map[string]PushToken    `json:"pushTokens"`
}

type Store struct {
	mu                sync.RWMutex
	path              string
	snapshot          snapshot
	lastDevicePersist map[string]int64
}

func Open(dataDir string) (*Store, error) {
	store := &Store{
		path:              filepath.Join(dataDir, "state.json"),
		lastDevicePersist: map[string]int64{},
		snapshot: snapshot{
			Users:         map[string]User{},
			RefreshTokens: map[string]RefreshToken{},
			Devices:       map[string]Device{},
			PushTokens:    map[string]PushToken{},
		},
	}
	data, err := os.ReadFile(store.path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}
	if err := json.Unmarshal(data, &store.snapshot); err != nil {
		return nil, fmt.Errorf("parse state: %w", err)
	}
	store.ensureMaps()
	now := time.Now().UnixMilli()
	for deviceID := range store.snapshot.Devices {
		store.lastDevicePersist[deviceID] = now
	}
	return store, nil
}

func (s *Store) ensureMaps() {
	if s.snapshot.Users == nil {
		s.snapshot.Users = map[string]User{}
	}
	if s.snapshot.RefreshTokens == nil {
		s.snapshot.RefreshTokens = map[string]RefreshToken{}
	}
	if s.snapshot.Devices == nil {
		s.snapshot.Devices = map[string]Device{}
	}
	if s.snapshot.PushTokens == nil {
		s.snapshot.PushTokens = map[string]PushToken{}
	}
}

func (s *Store) FindOrCreateUser(subject, email, displayName string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, user := range s.snapshot.Users {
		if user.Subject == subject {
			if email != "" {
				user.Email = email
			}
			if displayName != "" {
				user.DisplayName = displayName
			}
			s.snapshot.Users[user.ID] = user
			return user, s.persistLocked()
		}
	}
	user := User{ID: newID("usr"), Subject: subject, Email: email, DisplayName: displayName, CreatedAt: time.Now().UnixMilli()}
	if user.DisplayName == "" {
		user.DisplayName = email
	}
	s.snapshot.Users[user.ID] = user
	return user, s.persistLocked()
}

func (s *Store) User(id string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.snapshot.Users[id]
	return user, ok
}

func (s *Store) UpdateUser(user User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.snapshot.Users[user.ID]; !ok {
		return errors.New("user not found")
	}
	s.snapshot.Users[user.ID] = user
	return s.persistLocked()
}

func (s *Store) PutRefreshToken(token RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshot.RefreshTokens[token.Hash] = token
	return s.persistLocked()
}

func (s *Store) ConsumeRefreshToken(hash string) (RefreshToken, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.snapshot.RefreshTokens[hash]
	if !ok || token.ExpiresAt <= time.Now().Unix() {
		delete(s.snapshot.RefreshTokens, hash)
		return RefreshToken{}, false, s.persistLocked()
	}
	delete(s.snapshot.RefreshTokens, hash)
	return token, true, s.persistLocked()
}

func (s *Store) DeleteRefreshTokens(userID, deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, token := range s.snapshot.RefreshTokens {
		if token.UserID == userID && (deviceID == "" || token.DeviceID == deviceID) {
			delete(s.snapshot.RefreshTokens, hash)
		}
	}
	return s.persistLocked()
}

func (s *Store) UpsertDevice(device Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, ok := s.snapshot.Devices[device.DeviceID]; ok && current.UserID == device.UserID && device.ManualName == nil {
		device.ManualName = current.ManualName
	}
	s.snapshot.Devices[device.DeviceID] = device
	s.lastDevicePersist[device.DeviceID] = time.Now().UnixMilli()
	return s.persistLocked()
}

func (s *Store) TouchDevice(userID, deviceID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	device, ok := s.snapshot.Devices[deviceID]
	if !ok || device.UserID != userID {
		return nil
	}
	device.LastSeenAt = at.UnixMilli()
	s.snapshot.Devices[deviceID] = device
	if device.LastSeenAt-s.lastDevicePersist[deviceID] < int64(5*time.Minute/time.Millisecond) {
		return nil
	}
	s.lastDevicePersist[deviceID] = device.LastSeenAt
	return s.persistLocked()
}

func (s *Store) Device(userID, deviceID string) (Device, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	device, ok := s.snapshot.Devices[deviceID]
	return device, ok && device.UserID == userID
}

func (s *Store) Devices(userID string) []Device {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Device, 0)
	for _, device := range s.snapshot.Devices {
		if device.UserID == userID {
			result = append(result, device)
		}
	}
	return result
}

func (s *Store) RenameDevice(userID, deviceID string, name *string) (Device, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	device, ok := s.snapshot.Devices[deviceID]
	if !ok || device.UserID != userID {
		return Device{}, false, nil
	}
	device.ManualName = name
	s.snapshot.Devices[deviceID] = device
	return device, true, s.persistLocked()
}

func (s *Store) DeleteDevice(userID, deviceID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	device, ok := s.snapshot.Devices[deviceID]
	if !ok || device.UserID != userID {
		return false, nil
	}
	delete(s.snapshot.Devices, deviceID)
	delete(s.lastDevicePersist, deviceID)
	for hash, token := range s.snapshot.RefreshTokens {
		if token.UserID == userID && token.DeviceID == deviceID {
			delete(s.snapshot.RefreshTokens, hash)
		}
	}
	for key, token := range s.snapshot.PushTokens {
		if token.UserID == userID && token.DeviceID == deviceID {
			delete(s.snapshot.PushTokens, key)
		}
	}
	return true, s.persistLocked()
}

func (s *Store) PutPushToken(token PushToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshot.PushTokens[tokenKey(token.UserID, token.Token)] = token
	return s.persistLocked()
}

func (s *Store) DeletePushToken(userID, deviceID, rawToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, token := range s.snapshot.PushTokens {
		if token.UserID == userID && token.DeviceID == deviceID && (rawToken == "" || token.Token == rawToken) {
			delete(s.snapshot.PushTokens, key)
		}
	}
	return s.persistLocked()
}

func (s *Store) persistLocked() error {
	data, err := json.MarshalIndent(s.snapshot, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func TokenHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func RandomToken(bytes int) string {
	buffer := make([]byte, bytes)
	if _, err := rand.Read(buffer); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buffer)
}

func newID(prefix string) string           { return prefix + "_" + RandomToken(12) }
func tokenKey(userID, token string) string { return userID + ":" + TokenHash(token) }
