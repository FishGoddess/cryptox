// Copyright 2023 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hash

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	stdhash "hash"

	"github.com/FishGoddess/cryptox/v2/bytes"
)

func hashHMAC(hashFunc func() stdhash.Hash, key bytes.Bytes, bs bytes.Bytes) (bytes.Bytes, error) {
	h := hmac.New(hashFunc, key)

	n, err := h.Write(bs)
	if err != nil {
		return nil, err
	}

	if n != len(bs) {
		return nil, fmt.Errorf("hash: hashed n %d != len(bs) %d", n, len(bs))
	}

	return h.Sum(nil), nil
}

// MD5HMAC uses hmac-md5 to hash bs and returns an error if failed.
func MD5HMAC(key bytes.Bytes, bs bytes.Bytes) (bytes.Bytes, error) {
	return hashHMAC(md5.New, key, bs)
}

// SHA1HMAC uses hmac-sha1 to hash bs and returns an error if failed.
func SHA1HMAC(key bytes.Bytes, bs bytes.Bytes) (bytes.Bytes, error) {
	return hashHMAC(sha1.New, key, bs)
}

// SHA224HMAC uses hmac-sha224 to hash bs and returns an error if failed.
func SHA224HMAC(key bytes.Bytes, bs bytes.Bytes) (bytes.Bytes, error) {
	return hashHMAC(sha256.New224, key, bs)
}

// SHA256HMAC uses hmac-sha256 to hash bs and returns an error if failed.
func SHA256HMAC(key bytes.Bytes, bs bytes.Bytes) (bytes.Bytes, error) {
	return hashHMAC(sha256.New, key, bs)
}

// SHA384HMAC uses hmac-sha384 to hash bs and returns an error if failed.
func SHA384HMAC(key bytes.Bytes, bs bytes.Bytes) (bytes.Bytes, error) {
	return hashHMAC(sha512.New384, key, bs)
}

// SHA512HMAC uses hmac-sha512 to hash bs and returns an error if failed.
func SHA512HMAC(key bytes.Bytes, bs bytes.Bytes) (bytes.Bytes, error) {
	return hashHMAC(sha512.New, key, bs)
}
