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

	"github.com/FishGoddess/cryptox/bytes/encoding"
)

type hashFunc = func() stdhash.Hash

func hash(hashFunc hashFunc, key []byte, bs []byte, encoding encoding.Encoding) []byte {
	h := hmac.New(hashFunc, key)
	h.Write(bs)

	bs = h.Sum(nil)
	bs = encoding.Encode(bs)
	return bs
}

// MD5 uses hmac-md5 to hash bs and returns an error if failed.
func MD5(key []byte, bs []byte, encoding encoding.Encoding) []byte {
	return hash(md5.New, key, bs, encoding)
}

// SHA1 uses hmac-sha1 to hash bs and returns an error if failed.
func SHA1(key []byte, bs []byte, encoding encoding.Encoding) []byte {
	return hash(sha1.New, key, bs, encoding)
}

// SHA224 uses hmac-sha224 to hash bs and returns an error if failed.
func SHA224(key []byte, bs []byte, encoding encoding.Encoding) []byte {
	return hash(sha256.New224, key, bs, encoding)
}

// SHA256 uses hmac-sha256 to hash bs and returns an error if failed.
func SHA256(key []byte, bs []byte, encoding encoding.Encoding) []byte {
	return hash(sha256.New, key, bs, encoding)
}

// SHA384 uses hmac-sha384 to hash bs and returns an error if failed.
func SHA384(key []byte, bs []byte, encoding encoding.Encoding) []byte {
	return hash(sha512.New384, key, bs, encoding)
}

// SHA512 uses hmac-sha512 to hash bs and returns an error if failed.
func SHA512(key []byte, bs []byte, encoding encoding.Encoding) []byte {
	return hash(sha512.New, key, bs, encoding)
}
