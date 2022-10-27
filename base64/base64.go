// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package base64

import "encoding/base64"

func Encode(plain []byte) string {
	return base64.StdEncoding.EncodeToString(plain)
}

func Decode(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}
