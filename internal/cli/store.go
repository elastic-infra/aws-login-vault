package cli

import (
	"github.com/elastic-infra/aws-login-vault/internal/keychain"
)

// openStore resolves root-level flags into a keychain.Store, validating the
// backend selector before opening.
func openStore(sf *storeFlags) (*keychain.Store, error) {
	backend, err := keychain.ParseBackend(sf.backendRaw)
	if err != nil {
		return nil, err
	}
	return keychain.Open(keychain.Options{Backend: backend})
}
