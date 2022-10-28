// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

// copyBytes copies bs to a new byte slice.
func copyBytes(bs []byte) []byte {
	newSlice := make([]byte, len(bs))
	copy(newSlice, bs)

	return newSlice
}
