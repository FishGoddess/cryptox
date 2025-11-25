// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hash

import (
	"crypto/md5"

	"github.com/FishGoddess/cryptox/bytes/encoding"
)

// MD5 uses md5 to hash bs.
func MD5(bs []byte, encoding encoding.Encoding) []byte {
	sum := md5.Sum(bs)
	return encoding.Encode(sum[:])
}
