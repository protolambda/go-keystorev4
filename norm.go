package keystorev4

import (
	"golang.org/x/text/unicode/norm"
	"unicode/utf8"
)

// NormalizePassphrase transforms a passphrase for usage in the keystore.
//
// The password is a string of arbitrary unicode characters. The password is first converted to its NFKD representation,
// then the control codes (specified below) are stripped from the password and finally it is UTF-8 encoded.
//
// Stripped control codes:
// C0: 0x00 - 0x1F (inclusive)
// C1: 0x80 - 0x9F (inclusive)
// Delete: 7F
func NormalizePassphrase(passphrase []byte) []byte {
	// add enough capacity, output is not larger than input (new allocation otherwise, still safe)
	output := make([]byte, 0, len(passphrase))

	// Iterate over passphrase rune by rune to convert to NFKD presentation
	var iter norm.Iter
	iter.Init(norm.NFKD, passphrase)

	// tmp buffer, should be big enough for most runes, but may be expanded if necessary
	tmp := make([]byte, 0, 10)
	for !iter.Done() {
		runeBytes := iter.Next()
		// Decoding to get the UTF-8 rune size
		// TODO: can we not use len(runeBytes)?
		r, size := utf8.DecodeRune(runeBytes)

		// expand tmp buffer if necessary
		if cap(tmp) < size {
			tmp = make([]byte, size, size)
		} else {
			tmp = tmp[:size]
		}

		utf8.EncodeRune(tmp, r)

		// EIP-2335: he C0, C1, and Delete control codes are not valid characters
		//  in the password and should therefore be stripped from the password.
		if size == 1 {
			if c := tmp[0]; (c <= 0x1F) || (0x80 <= c && c <= 0x9F) || (c == 0x7F) {
				continue
			}
		}
		output = norm.NFKD.Append(output, tmp...)
	}
	return passphrase
}
