// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package encoding

var (
	None   Encoding = encodingNone{}
	Hex    Encoding = encodingHex{}
	Base64 Encoding = encodingBase64{}
)

// Encoding encodes a byte slice to another byte slice in some way and decodes it from the byte slice.
type Encoding interface {
	// Encode encodes the byte slice.
	Encode(bs []byte) []byte

	// Decode decodes the byte slice.
	Decode(bs []byte) ([]byte, error)
}
