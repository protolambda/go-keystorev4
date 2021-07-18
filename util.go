package keystorev4

import (
	"encoding/hex"
	"errors"
)

type JsonBytes []byte

func (v *JsonBytes) UnmarshalText(text []byte) error {
	if v == nil {
		return errors.New("cannot decode JsonBytes into nil")
	}
	// be lenient, and accept the 0x prefix.
	if len(text) >= 2 && text[0] == '0' && text[1] == 'x' {
		text = text[2:]
	}
	l := hex.DecodedLen(len(text))
	// re-use bytes if possible
	if cap(*v) >= l {
		*v = (*v)[:l]
	} else {
		*v = make([]byte, l, l)
	}
	_, err := hex.Decode(*v, text)
	return err
}

func (v *JsonBytes) MarshalText() ([]byte, error) {
	if v == nil {
		return nil, nil
	}
	out := make([]byte, len(*v)*2, len(*v)*2)
	hex.Encode(out, *v)
	return out, nil
}
