// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package bytes

import (
	"encoding/base64"
	"encoding/hex"
)

// Hex encodes bs to a hex string.
func Hex(bs []byte) string {
	return hex.EncodeToString(bs)
}

// Base64 encodes bs to a base64 string.
func Base64(bs []byte) string {
	return base64.StdEncoding.EncodeToString(bs)
}

// ParseHex parses a hex string to a bytes.
func ParseHex(hexString string) ([]byte, error) {
	return hex.DecodeString(hexString)
}

// ParseBase64 parses a base64 string to a bytes.
func ParseBase64(base64String string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(base64String)
}
