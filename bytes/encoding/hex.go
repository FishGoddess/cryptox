// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package encoding

import "encoding/hex"

type encodingHex struct{}

// Encode encodes the byte slice with hex encoding.
func (encodingHex) Encode(bs []byte) []byte {
	n := hex.EncodedLen(len(bs))
	buffer := make([]byte, n)

	n = hex.Encode(buffer, bs)
	return buffer[:n]
}

// Decode decodes the byte slice with hex encoding.
func (encodingHex) Decode(bs []byte) ([]byte, error) {
	n := hex.DecodedLen(len(bs))
	buffer := make([]byte, n)

	n, err := hex.Decode(buffer, bs)
	if err != nil {
		return nil, err
	}

	return buffer[:n], nil
}
