// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package padding

var (
	None  Padding = paddingNone{}
	Zero  Padding = paddingZero{}
	PKCS5 Padding = paddingPKCS5{}
	PKCS7 Padding = paddingPKCS7{}
)

// Padding will pad a byte slice with some bytes and unpad them with the same bytes.
type Padding interface {
	// Pad pads some bytes to the byte slice.
	Pad(bs []byte, blockSize int) []byte

	// Unpad unpads the bytes from the byte slice.
	Unpad(bs []byte, blockSize int) ([]byte, error)
}
