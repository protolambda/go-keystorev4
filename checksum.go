package keystorev4

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
)

var ChecksumMismatchErr = errors.New("checksum mismatch")

type ChecksumParams interface {
	// Computes the checksum
	Checksum(decryptionKey []byte, cipherMessage []byte) ([]byte, error)
	Function() string
}

type HashChecksumParams struct {
	Hasher func() hash.Hash `json:"-"`
	// Name is already declared in the Function field
	Name string `json:"-"`
}

var _ ChecksumParams = (*HashChecksumParams)(nil)

func (hc *HashChecksumParams) Checksum(decryptionKey []byte, cipherMessage []byte) ([]byte, error) {
	if len(decryptionKey) < 32 {
		return nil, errors.New("decryption key too short")
	}
	h := hc.Hasher()
	h.Write(decryptionKey[16:32])
	h.Write(cipherMessage)
	return h.Sum(nil), nil
}

func (hc *HashChecksumParams) Function() string {
	return hc.Name
}

var Sha256ChecksumParams = &HashChecksumParams{Hasher: sha256.New, Name: "sha256"}

type KeystoreChecksumModule struct {
	Function string         `json:"function"`
	Params   ChecksumParams `json:"params"`
	Message  JsonBytes      `json:"message"`
}

func (s *KeystoreChecksumModule) UnmarshalJSON(data []byte) error {
	if s == nil {
		return errors.New("cannot decode KeystoreChecksumModule into nil")
	}
	return unmarshalModule(data, &s.Function, &s.Message, func(function string) (interface{}, error) {
		switch function {
		case "sha256":
			s.Params = Sha256ChecksumParams
		default:
			return nil, fmt.Errorf("unrecognized checksum params function type: %q", function)
		}
		return s.Params, nil
	})
}
