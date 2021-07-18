package keystorev4

import (
	"bytes"
	"fmt"
)

type KeystoreCrypto struct {
	KDF      KeystoreKDFModule      `json:"kdf"`
	Checksum KeystoreChecksumModule `json:"checksum"`
	Cipher   KeystoreCipherModule   `json:"cipher"`
}

func (v *KeystoreCrypto) Decrypt(passphrase []byte) (secret []byte, err error) {
	normedPassphrase := NormalizePassphrase(passphrase)
	decryptionKey, err := v.KDF.Params.DecryptionKey(normedPassphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to get decryption key: %w", err)
	}
	checksum, err := v.Checksum.Params.Checksum(decryptionKey, v.Cipher.Message)
	if err != nil {
		return nil, fmt.Errorf("failed to compute checksum: %w", err)
	}
	if !bytes.Equal(v.Checksum.Message, checksum) {
		return nil, ChecksumMismatchErr
	}
	secret, err = v.Cipher.Params.Decipher(v.Cipher.Message, decryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decipher secret: %w", err)
	}
	return secret, nil
}

func Encrypt(secret []byte, passphrase []byte, kdfParams KDFParams, checksumParams ChecksumParams, cipherParams CipherParams) (*KeystoreCrypto, error) {
	normedPassphrase := NormalizePassphrase(passphrase)
	decryptionKey, err := kdfParams.DecryptionKey(normedPassphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to get decryption key: %w", err)
	}
	cipherMessage, err := cipherParams.Encipher(decryptionKey, secret)
	if err != nil {
		return nil, fmt.Errorf("failed to encipher secret: %w", err)
	}
	checksum, err := checksumParams.Checksum(decryptionKey, cipherMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to compute checksum: %w", err)
	}
	return &KeystoreCrypto{
		KDF: KeystoreKDFModule{
			Function: kdfParams.Function(),
			Params:   kdfParams,
			Message:  nil, // purposefully empty
		},
		Checksum: KeystoreChecksumModule{
			Function: checksumParams.Function(),
			Params:   checksumParams,
			Message:  checksum,
		},
		Cipher: KeystoreCipherModule{
			Function: cipherParams.Function(),
			Params:   cipherParams,
			Message:  cipherMessage,
		},
	}, nil
}
