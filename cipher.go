package keystorev4

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

type CipherParams interface {
	Decipher(cipherMsg []byte, decryptionKey []byte) (secret []byte, err error)
	Encipher(decryptionKey []byte, secret []byte) (cipherMsg []byte, err error)
	Function() string
}

type AES128CTRParams struct {
	IV JsonBytes `json:"iv"`
}

func NewAES128CTRParams() (*AES128CTRParams, error) {
	// Random IV
	var iv [16]byte
	if _, err := rand.Read(iv[:]); err != nil {
		return nil, err
	}
	return &AES128CTRParams{IV: iv[:]}, nil
}

func (a *AES128CTRParams) Decipher(cipherMsg []byte, decryptionKey []byte) (secret []byte, err error) {
	if len(decryptionKey) < 32 {
		return nil, errors.New("decryption key too short")
	}
	aesCipher, err := aes.NewCipher(decryptionKey[:16])
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(aesCipher, a.IV)
	out := make([]byte, len(cipherMsg), len(cipherMsg))
	stream.XORKeyStream(out, cipherMsg)
	return out, nil
}

func (a *AES128CTRParams) Encipher(decryptionKey []byte, secret []byte) (cipherMsg []byte, err error) {
	if len(decryptionKey) < 32 {
		return nil, errors.New("decryption key too short")
	}
	cipherMsg = make([]byte, len(secret), len(secret))
	aesCipher, err := aes.NewCipher(decryptionKey[:16])
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(aesCipher, a.IV)
	stream.XORKeyStream(cipherMsg, secret)
	return cipherMsg, nil
}

func (a *AES128CTRParams) Function() string {
	return "aes-128-ctr"
}

var _ CipherParams = (*AES128CTRParams)(nil)

type KeystoreCipherModule struct {
	Function string       `json:"function"`
	Params   CipherParams `json:"params"`
	Message  JsonBytes    `json:"message"`
}

func (s *KeystoreCipherModule) UnmarshalJSON(data []byte) error {
	if s == nil {
		return errors.New("cannot decode KeystoreCipherModule into nil")
	}
	return unmarshalModule(data, &s.Function, &s.Message, func(function string) (interface{}, error) {
		switch function {
		case "aes-128-ctr":
			s.Params = new(AES128CTRParams)
		default:
			return nil, fmt.Errorf("unrecognized cipher params function type: %q", function)
		}
		return s.Params, nil
	})
}
