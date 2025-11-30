// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package encoding

type encodingNone struct{}

// Encode returns the original byte slice.
func (encodingNone) Encode(bs []byte) []byte {
	return bs
}

// Decode returns the original byte slice.
func (encodingNone) Decode(bs []byte) ([]byte, error) {
	return bs, nil
}
