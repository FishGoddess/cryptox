// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hex

import "encoding/hex"

func Encode(plain []byte) string {
	return hex.EncodeToString(plain)
}

func Decode(encoded string) ([]byte, error) {
	return hex.DecodeString(encoded)
}
