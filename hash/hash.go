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

// MD5 uses md5 to hash data.
func MD5(data []byte, opts ...Option) []byte {
	conf := newConfig().Apply(opts...)

	sum := md5.Sum(data)
	return conf.encoding.Encode(sum[:])
}

// SHA1 uses sha1 to hash data.
func SHA1(data []byte, opts ...Option) []byte {
	conf := newConfig().Apply(opts...)

	sum := sha1.Sum(data)
	return conf.encoding.Encode(sum[:])
}

// SHA224 uses sha224 to hash data.
func SHA224(data []byte, opts ...Option) []byte {
	conf := newConfig().Apply(opts...)

	sum := sha256.Sum224(data)
	return conf.encoding.Encode(sum[:])
}

// SHA256 uses sha256 to hash data.
func SHA256(data []byte, opts ...Option) []byte {
	conf := newConfig().Apply(opts...)

	sum := sha256.Sum256(data)
	return conf.encoding.Encode(sum[:])
}

// SHA384 uses sha384 to hash data.
func SHA384(data []byte, opts ...Option) []byte {
	conf := newConfig().Apply(opts...)

	sum := sha512.Sum384(data)
	return conf.encoding.Encode(sum[:])
}

// SHA512 uses sha512 to hash data.
func SHA512(data []byte, opts ...Option) []byte {
	conf := newConfig().Apply(opts...)

	sum := sha512.Sum512(data)
	return conf.encoding.Encode(sum[:])
}
