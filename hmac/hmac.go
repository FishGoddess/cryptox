// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hmac

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	stdhash "hash"
)

type hashFunc = func() stdhash.Hash

func hash(hashFunc hashFunc, data []byte, key []byte, opts ...Option) []byte {
	conf := newConfig().Apply(opts...)

	h := hmac.New(hashFunc, key)
	h.Write(data)

	data = h.Sum(nil)
	data = conf.encoding.Encode(data)
	return data
}

// MD5 uses hmac-md5 to hash data and returns an error if failed.
func MD5(data []byte, key []byte, opts ...Option) []byte {
	return hash(md5.New, data, key, opts...)
}

// SHA1 uses hmac-sha1 to hash data and returns an error if failed.
func SHA1(data []byte, key []byte, opts ...Option) []byte {
	return hash(sha1.New, data, key, opts...)
}

// SHA224 uses hmac-sha224 to hash data and returns an error if failed.
func SHA224(data []byte, key []byte, opts ...Option) []byte {
	return hash(sha256.New224, data, key, opts...)
}

// SHA256 uses hmac-sha256 to hash data and returns an error if failed.
func SHA256(data []byte, key []byte, opts ...Option) []byte {
	return hash(sha256.New, data, key, opts...)
}

// SHA384 uses hmac-sha384 to hash data and returns an error if failed.
func SHA384(data []byte, key []byte, opts ...Option) []byte {
	return hash(sha512.New384, data, key, opts...)
}

// SHA512 uses hmac-sha512 to hash data and returns an error if failed.
func SHA512(data []byte, key []byte, opts ...Option) []byte {
	return hash(sha512.New, data, key, opts...)
}
