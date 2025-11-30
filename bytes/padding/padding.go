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

// Padding pads some bytes to the byte slice and unpad them from the byte slice.
type Padding interface {
	// Pad pads some bytes to the byte slice.
	Pad(bs []byte, blockSize int) []byte

	// Unpad unpads some bytes from the byte slice.
	Unpad(bs []byte, blockSize int) ([]byte, error)
}
