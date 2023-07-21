// Copyright 2023 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hash

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"

	"github.com/FishGoddess/cryptox"
)

// MD5 uses md5 to hash bs.
func MD5(bs cryptox.Bytes) cryptox.Bytes {
	sum := md5.Sum(bs)
	return sum[:]
}

// SHA1 uses sha1 to hash bs.
func SHA1(bs cryptox.Bytes) cryptox.Bytes {
	sum := sha1.Sum(bs)
	return sum[:]
}

// SHA224 uses sha224 to hash bs.
func SHA224(bs cryptox.Bytes) cryptox.Bytes {
	sum := sha256.Sum224(bs)
	return sum[:]
}

// SHA256 uses sha256 to hash bs.
func SHA256(bs cryptox.Bytes) cryptox.Bytes {
	sum := sha256.Sum256(bs)
	return sum[:]
}

// SHA384 uses sha384 to hash bs.
func SHA384(bs cryptox.Bytes) cryptox.Bytes {
	sum := sha512.Sum384(bs)
	return sum[:]
}

// SHA512 uses sha512 to hash bs.
func SHA512(bs cryptox.Bytes) cryptox.Bytes {
	sum := sha512.Sum512(bs)
	return sum[:]
}
