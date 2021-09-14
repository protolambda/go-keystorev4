package keystorev4

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

type KDFParams interface {
	DecryptionKey(normedPassphrase []byte) ([]byte, error)
	Function() string
}

type ScryptParams struct {
	Dklen int       `json:"dklen"`
	N     int       `json:"n"`
	P     int       `json:"p"`
	R     int       `json:"r"`
	Salt  JsonBytes `json:"salt"`
}

func NewScryptParams() (*ScryptParams, error) {
	var salt [32]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, err
	}
	return &ScryptParams{
		Dklen: 32,
		N:     262144,
		P:     1,
		R:     8,
		Salt:  salt[:],
	}, nil
}

var _ KDFParams = (*ScryptParams)(nil)

func (sp *ScryptParams) DecryptionKey(normedPassphrase []byte) ([]byte, error) {
	return scrypt.Key(normedPassphrase, sp.Salt, sp.N, sp.R, sp.P, sp.Dklen)
}

func (sp *ScryptParams) Function() string {
	return "scrypt"
}

type PBKDF2Params struct {
	Dklen int       `json:"dklen"`
	C     int       `json:"c"`
	Prf   string    `json:"prf"`
	Salt  JsonBytes `json:"salt"`
}

func NewPBKDF2Params() (*PBKDF2Params, error) {
	var salt [32]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, err
	}
	return &PBKDF2Params{
		Dklen: 32,
		C:     262144,
		Prf:   "hmac-sha256",
		Salt:  salt[:],
	}, nil
}

var _ KDFParams = (*PBKDF2Params)(nil)

func (sp *PBKDF2Params) DecryptionKey(normedPassphrase []byte) ([]byte, error) {
	switch sp.Prf {
	case "hmac-sha256":
		return pbkdf2.Key(normedPassphrase, sp.Salt, sp.C, sp.Dklen, sha256.New), nil
	// TODO: support more PRF maybe?
	default:
		return nil, fmt.Errorf("PRF %q is not supported", sp.Prf)
	}
}

func (sp *PBKDF2Params) Function() string {
	return "pbkdf2"
}

type KeystoreKDFModule struct {
	Function string    `json:"function"`
	Params   KDFParams `json:"params"`
	Message  JsonBytes `json:"message"`
}

func (s *KeystoreKDFModule) UnmarshalJSON(data []byte) error {
	if s == nil {
		return errors.New("cannot decode KeystoreKDFModule into nil")
	}
	err := unmarshalModule(data, &s.Function, &s.Message, func(function string) (interface{}, error) {
		switch function {
		case "scrypt":
			s.Params = new(ScryptParams)
		case "pbkdf2":
			s.Params = new(PBKDF2Params)
		default:
			return nil, fmt.Errorf("unrecognized KDF params function type: %q", function)
		}
		return s.Params, nil
	})
	if err != nil {
		return err
	}
	if len(s.Message) != 0 {
		return fmt.Errorf("KDF 'message' module field was expected to be empty, but got: %x", s.Message)
	}
	return nil
}
