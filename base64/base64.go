package base64

import "encoding/base64"

func Encode(plain []byte) string {
	return base64.StdEncoding.EncodeToString(plain)
}

func Decode(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}
