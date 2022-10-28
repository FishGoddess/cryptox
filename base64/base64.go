// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package base64

import "encoding/base64"

// Encode encodes data to string in base64.
func Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// Decode decodes data in hex to byte and returns an error if failed.
func Decode(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}
