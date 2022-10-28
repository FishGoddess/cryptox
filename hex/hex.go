// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hex

import "encoding/hex"

// Encode encodes data to string in hex.
func Encode(data []byte) string {
	return hex.EncodeToString(data)
}

// Decode decodes data in hex to byte and returns an error if failed.
func Decode(data string) ([]byte, error) {
	return hex.DecodeString(data)
}
