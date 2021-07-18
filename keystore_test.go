package keystorev4

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type testCase struct {
	Path       string
	Passphrase string
	Secret     string
}

func TestKeystore_Decrypt(t *testing.T) {
	// TODO: maybe walk whole test dir when adding more test-cases
	cases := []testCase{
		{"eip2335_pbkdf2_example.json", "0x7465737470617373776f7264f09f9491", "0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"},
		{"eip2335_scrypt_example.json", "0x7465737470617373776f7264f09f9491", "0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"},
	}
	for _, testCase := range cases {
		t.Run(testCase.Path, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("tests", testCase.Path))
			if err != nil {
				t.Fatalf("failed to read test keystore file: %v", err)
			}
			var keystore Keystore
			if err := json.Unmarshal(data, &keystore); err != nil {
				t.Fatalf("failed to decode keystore: %v", err)
			}
			passphrase, err := hex.DecodeString(testCase.Passphrase[2:])
			if err != nil {
				t.Fatalf("failed to decode passphrase: %v", err)
			}
			secret, err := keystore.Decrypt(passphrase)
			if err != nil {
				t.Fatalf("failed to decrypt keystore: %v", err)
			}
			expectedSecret, err := hex.DecodeString(testCase.Secret[2:])
			if err != nil {
				t.Fatalf("failed to decode expected secret: %v", err)
			}
			if !bytes.Equal(secret, expectedSecret) {
				t.Fatalf("got different secret than expected:\ngot: %x\nexpected: %x", secret, expectedSecret)
			}
		})
	}
}
