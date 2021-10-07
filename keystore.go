package keystorev4

import (
	"fmt"
	"github.com/google/uuid"
)

// Keystore as defined in EIP-2335, designed for BLS12-381 secret keys.
type Keystore struct {
	Crypto      KeystoreCrypto `json:"crypto"`
	Description string         `json:"description,omitempty"`
	Pubkey      JsonBytes      `json:"pubkey,omitempty"`
	// Path used in HD derivation.
	// EIP-2335 marks this as required field, but it may not exist, thus sometimes empty here.
	Path    string    `json:"path"`
	UUID    uuid.UUID `json:"uuid"`
	Version uint      `json:"version"`
}

// Decrypts the given keystore (up to user to unmarshal from JSON), returns the secret
// The keystore version is validated, but Path and Pubkey are NOT.
func (v *Keystore) Decrypt(passphrase []byte) (secret []byte, err error) {
	if v.Version != 4 {
		return nil, fmt.Errorf("expected keystore version 4, but got %d", v.Version)
	}
	return v.Crypto.Decrypt(passphrase)
}

// EncryptToKeystore encrypts a secret with the given passphrase,
// using the default parameters, new random 32-byte salts, PBKDF2 as KDF, AES-128-CTR as cipher, SHA-256 as checksum.
//
// The keystore Description, Pubkey and Path fields are not initialized, and can be set by the caller.
func EncryptToKeystore(secret []byte, passphrase []byte) (*Keystore, error) {
	kdfParams, err := NewPBKDF2Params()
	if err != nil {
		return nil, fmt.Errorf("failed to create PBKDF2 params: %w", err)
	}
	cipherParams, err := NewAES128CTRParams()
	if err != nil {
		return nil, fmt.Errorf("failed to create AES128CTR params: %w", err)
	}
	crypto, err := Encrypt(secret, passphrase, kdfParams, Sha256ChecksumParams, cipherParams)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt secret: %w", err)
	}
	id, err := uuid.NewUUID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate UUID: %w", err)
	}
	return &Keystore{
		Crypto:      *crypto,
		Description: "",
		Pubkey:      nil,
		Path:        "",
		UUID:        id,
		Version:     4,
	}, nil
}
