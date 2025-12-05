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
	Encode(data []byte) []byte

	// Decode decodes the byte slice.
	Decode(data []byte) ([]byte, error)
}

type None struct{}

// Encode returns the original byte slice.
func (None) Encode(data []byte) []byte {
	return data
}

// Decode returns the original byte slice.
func (None) Decode(data []byte) ([]byte, error) {
	return data, nil
}

type Hex struct{}

// Encode encodes the byte slice with hex encoding.
func (Hex) Encode(data []byte) []byte {
	n := hex.EncodedLen(len(data))
	buffer := make([]byte, n)

	n = hex.Encode(buffer, data)
	return buffer[:n]
}

// Decode decodes the byte slice with hex encoding.
func (Hex) Decode(data []byte) ([]byte, error) {
	n := hex.DecodedLen(len(data))
	buffer := make([]byte, n)

	n, err := hex.Decode(buffer, data)
	if err != nil {
		return nil, err
	}

	return buffer[:n], nil
}

type Base64 struct{}

// Encode encodes the byte slice with base64 encoding.
func (Base64) Encode(data []byte) []byte {
	enc := base64.StdEncoding
	n := enc.EncodedLen(len(data))
	buffer := make([]byte, n)

	enc.Encode(buffer, data)
	return buffer[:n]
}

// Decode decodes the byte slice with base64 encoding.
func (Base64) Decode(data []byte) ([]byte, error) {
	enc := base64.StdEncoding
	n := enc.DecodedLen(len(data))
	buffer := make([]byte, n)

	n, err := enc.Decode(buffer, data)
	if err != nil {
		return nil, err
	}

	return buffer[:n], nil
}
