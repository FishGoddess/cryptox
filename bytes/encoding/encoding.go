// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package encoding

import (
	"encoding/base64"
	"encoding/hex"
)

type Encoding interface {
	// Encode encodes the byte slice.
	Encode(bs []byte) []byte

	// Decode decodes the byte slice.
	Decode(bs []byte) ([]byte, error)
}

type None struct{}

// Encode returns the original byte slice.
func (None) Encode(bs []byte) []byte {
	return bs
}

// Decode returns the original byte slice.
func (None) Decode(bs []byte) ([]byte, error) {
	return bs, nil
}

type Hex struct{}

// Encode encodes the byte slice with hex encoding.
func (Hex) Encode(bs []byte) []byte {
	n := hex.EncodedLen(len(bs))
	buffer := make([]byte, n)

	n = hex.Encode(buffer, bs)
	return buffer[:n]
}

// Decode decodes the byte slice with hex encoding.
func (Hex) Decode(bs []byte) ([]byte, error) {
	n := hex.DecodedLen(len(bs))
	buffer := make([]byte, n)

	n, err := hex.Decode(buffer, bs)
	if err != nil {
		return nil, err
	}

	return buffer[:n], nil
}

type Base64 struct{}

// Encode encodes the byte slice with base64 encoding.
func (Base64) Encode(bs []byte) []byte {
	enc := base64.StdEncoding
	n := enc.EncodedLen(len(bs))
	buffer := make([]byte, n)

	enc.Encode(buffer, bs)
	return buffer[:n]
}

// Decode decodes the byte slice with base64 encoding.
func (Base64) Decode(bs []byte) ([]byte, error) {
	enc := base64.StdEncoding
	n := enc.DecodedLen(len(bs))
	buffer := make([]byte, n)

	n, err := enc.Decode(buffer, bs)
	if err != nil {
		return nil, err
	}

	return buffer[:n], nil
}
