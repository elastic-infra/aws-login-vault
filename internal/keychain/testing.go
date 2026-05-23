package keychain

import "github.com/99designs/keyring"

// NewForTesting returns an in-memory Store backed by ArrayKeyring.
// Production code must use Open() instead.
func NewForTesting() *Store {
	return &Store{kr: keyring.NewArrayKeyring([]keyring.Item{})}
}
