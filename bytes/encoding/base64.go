// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package encoding

import "encoding/base64"

type encodingBase64 struct{}

// Encode encodes the byte slice with base64 encoding.
func (encodingBase64) Encode(bs []byte) []byte {
	enc := base64.StdEncoding
	n := enc.EncodedLen(len(bs))
	buffer := make([]byte, n)
	enc.Encode(buffer, bs)

	return buffer[:n]
}

// Decode decodes the byte slice with base64 encoding.
func (encodingBase64) Decode(bs []byte) ([]byte, error) {
	enc := base64.StdEncoding
	n := enc.DecodedLen(len(bs))
	buffer := make([]byte, n)

	n, err := enc.Decode(buffer, bs)
	if err != nil {
		return nil, err
	}

	return buffer[:n], nil
}
