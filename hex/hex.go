package hex

import "encoding/hex"

func Encode(plain []byte) string {
	return hex.EncodeToString(plain)
}

func Decode(encoded string) ([]byte, error) {
	return hex.DecodeString(encoded)
}
