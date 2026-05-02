package keychain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/99designs/keyring"
)

const (
	serviceName   = "aws-login-vault"
	keyPrefix     = "profile/"
	assumedPrefix = "assumed/"
)

// ErrNotFound is returned when a profile has no keychain entry.
var ErrNotFound = errors.New("keychain entry not found")

// Session is the complete persisted state for a profile.
// It carries the short-lived AWS credentials, the refresh token, and the DPoP
// private key used to bind the refresh token (must be reused on refresh).
type Session struct {
	SessionARN      string    `json:"sessionArn"`
	AccessKeyID     string    `json:"accessKeyId"`
	SecretAccessKey string    `json:"secretAccessKey"`
	SessionToken    string    `json:"sessionToken"`
	Expiration      time.Time `json:"expiration"`
	RefreshToken    string    `json:"refreshToken"`
	DPoPKeyPEM      string    `json:"dpopKeyPem"`
	Region          string    `json:"region"`
	ClientID        string    `json:"clientId"`
}

// Creds exposes the subset used for credential_process output.
func (s *Session) Creds() (akid, secret, token string, expiration time.Time, region string) {
	return s.AccessKeyID, s.SecretAccessKey, s.SessionToken, s.Expiration, s.Region
}

// AssumedSession is a cached AssumeRole result. It has no refresh capability
// on its own: when expired, the caller must re-AssumeRole from the base login
// session. Hence no RefreshToken or DPoP key here.
type AssumedSession struct {
	AccessKeyID     string    `json:"accessKeyId"`
	SecretAccessKey string    `json:"secretAccessKey"`
	SessionToken    string    `json:"sessionToken"`
	Expiration      time.Time `json:"expiration"`
	RoleARN         string    `json:"roleArn"`
	RoleSessionName string    `json:"roleSessionName"`
	SourceIdentity  string    `json:"sourceIdentity,omitempty"`
	Region          string    `json:"region"`
}

func (s *AssumedSession) Creds() (akid, secret, token string, expiration time.Time, region string) {
	return s.AccessKeyID, s.SecretAccessKey, s.SessionToken, s.Expiration, s.Region
}

type Store struct {
	kr keyring.Keyring
}

func Open() (*Store, error) {
	// All name fields are set to serviceName so entries land in a single
	// namespace ("aws-login-vault") regardless of which backend is selected.
	// AllowedBackends is ordered by preference: GUI session store first, then
	// the on-disk gpg-encrypted store, then the session-only kernel keyring.
	kr, err := keyring.Open(keyring.Config{
		ServiceName:              serviceName,
		KeychainName:             serviceName, // macOS only: ~/Library/Keychains/aws-login-vault.keychain-db
		KeychainTrustApplication: true,
		KeychainSynchronizable:   false,
		LibSecretCollectionName:  serviceName,
		PassPrefix:               serviceName,
		AllowedBackends: []keyring.BackendType{
			keyring.KeychainBackend,      // macOS
			keyring.SecretServiceBackend, // Linux GUI session (gnome-keyring / kwallet)
			keyring.PassBackend,          // Linux pass + gpg-agent
			keyring.KeyCtlBackend,        // Linux session-only fallback
		},
	})
	if err != nil {
		return nil, fmt.Errorf("open keychain: %w", err)
	}
	return &Store{kr: kr}, nil
}

func (s *Store) Save(profile string, sess *Session) error {
	data, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	return s.kr.Set(keyring.Item{
		Key:         keyName(profile),
		Data:        data,
		Label:       fmt.Sprintf("aws-login-vault: %s", profile),
		Description: "AWS Login session credentials",
	})
}

func (s *Store) Load(profile string) (*Session, error) {
	item, err := s.kr.Get(keyName(profile))
	if err != nil {
		if errors.Is(err, keyring.ErrKeyNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var sess Session
	if err := json.Unmarshal(item.Data, &sess); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}
	return &sess, nil
}

func (s *Store) Delete(profile string) error {
	err := s.kr.Remove(keyName(profile))
	if errors.Is(err, keyring.ErrKeyNotFound) {
		return ErrNotFound
	}
	return err
}

func (s *Store) List() ([]string, error) {
	keys, err := s.kr.Keys()
	if err != nil {
		return nil, err
	}
	profiles := make([]string, 0, len(keys))
	for _, k := range keys {
		if p, ok := strings.CutPrefix(k, keyPrefix); ok {
			profiles = append(profiles, p)
		}
	}
	return profiles, nil
}

// AssumedKey builds the keychain entry key for a cached AssumeRole result.
// Format: assumed/<profile>/<sha256(role-arn)>[/<source-identity>]
func AssumedKey(profile, roleARN, sourceIdentity string) string {
	h := sha256.Sum256([]byte(roleARN))
	key := assumedPrefix + profile + "/" + hex.EncodeToString(h[:])
	if sourceIdentity != "" {
		key += "/" + sourceIdentity
	}
	return key
}

func (s *Store) SaveAssumed(key string, sess *AssumedSession) error {
	data, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	return s.kr.Set(keyring.Item{
		Key:         key,
		Data:        data,
		Label:       fmt.Sprintf("aws-login-vault: %s", key),
		Description: "AWS Login AssumeRole cached credentials",
	})
}

func (s *Store) LoadAssumed(key string) (*AssumedSession, error) {
	item, err := s.kr.Get(key)
	if err != nil {
		if errors.Is(err, keyring.ErrKeyNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var sess AssumedSession
	if err := json.Unmarshal(item.Data, &sess); err != nil {
		return nil, fmt.Errorf("unmarshal assumed session: %w", err)
	}
	return &sess, nil
}

// DeleteAssumedForProfile removes every assumed-role cache entry for a profile.
// Used by logout so that stale role credentials don't survive a session rotation.
func (s *Store) DeleteAssumedForProfile(profile string) (int, error) {
	keys, err := s.kr.Keys()
	if err != nil {
		return 0, err
	}
	prefix := assumedPrefix + profile + "/"
	removed := 0
	for _, k := range keys {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		if err := s.kr.Remove(k); err != nil && !errors.Is(err, keyring.ErrKeyNotFound) {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

func keyName(profile string) string {
	return keyPrefix + profile
}
