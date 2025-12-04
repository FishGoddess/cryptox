// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hash

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
)

// MD5 uses md5 to hash bs.
func MD5(bs []byte, opts ...Option) []byte {
	conf := newConfig().Apply(opts...)

	sum := md5.Sum(bs)
	return conf.encoding.Encode(sum[:])
}

// SHA1 uses sha1 to hash bs.
func SHA1(bs []byte, opts ...Option) []byte {
	conf := newConfig().Apply(opts...)

	sum := sha1.Sum(bs)
	return conf.encoding.Encode(sum[:])
}

// SHA224 uses sha224 to hash bs.
func SHA224(bs []byte, opts ...Option) []byte {
	conf := newConfig().Apply(opts...)

	sum := sha256.Sum224(bs)
	return conf.encoding.Encode(sum[:])
}

// SHA256 uses sha256 to hash bs.
func SHA256(bs []byte, opts ...Option) []byte {
	conf := newConfig().Apply(opts...)

	sum := sha256.Sum256(bs)
	return conf.encoding.Encode(sum[:])
}

// SHA384 uses sha384 to hash bs.
func SHA384(bs []byte, opts ...Option) []byte {
	conf := newConfig().Apply(opts...)

	sum := sha512.Sum384(bs)
	return conf.encoding.Encode(sum[:])
}

// SHA512 uses sha512 to hash bs.
func SHA512(bs []byte, opts ...Option) []byte {
	conf := newConfig().Apply(opts...)

	sum := sha512.Sum512(bs)
	return conf.encoding.Encode(sum[:])
}
