package login

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

const ecPrivateKeyPEMType = "EC PRIVATE KEY"

func SerializeECPrivateKeyPEM(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}
	block := &pem.Block{Type: ecPrivateKeyPEMType, Bytes: der}
	return string(pem.EncodeToMemory(block)), nil
}

func ParseECPrivateKeyPEM(s string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil || block.Type != ecPrivateKeyPEMType {
		return nil, errors.New("invalid EC PRIVATE KEY PEM")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}
