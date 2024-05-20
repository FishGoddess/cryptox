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
	"fmt"
	stdhash "hash"

	"github.com/FishGoddess/cryptox"
)

func hash(hashFunc func() stdhash.Hash, key cryptox.Bytes, bs cryptox.Bytes) (cryptox.Bytes, error) {
	h := hmac.New(hashFunc, key)

	n, err := h.Write(bs)
	if err != nil {
		return nil, err
	}

	if n != len(bs) {
		return nil, fmt.Errorf("cryptox: hashed n %d != len(bs) %d", n, len(bs))
	}

	return h.Sum(nil), nil
}

// MD5 uses hmac-md5 to hash bs and returns an error if failed.
func MD5(key cryptox.Bytes, bs cryptox.Bytes) (cryptox.Bytes, error) {
	return hash(md5.New, key, bs)
}

// SHA1 uses hmac-sha1 to hash bs and returns an error if failed.
func SHA1(key cryptox.Bytes, bs cryptox.Bytes) (cryptox.Bytes, error) {
	return hash(sha1.New, key, bs)
}

// SHA224 uses hmac-sha224 to hash bs and returns an error if failed.
func SHA224(key cryptox.Bytes, bs cryptox.Bytes) (cryptox.Bytes, error) {
	return hash(sha256.New224, key, bs)
}

// SHA256 uses hmac-sha256 to hash bs and returns an error if failed.
func SHA256(key cryptox.Bytes, bs cryptox.Bytes) (cryptox.Bytes, error) {
	return hash(sha256.New, key, bs)
}

// SHA384 uses hmac-sha384 to hash bs and returns an error if failed.
func SHA384(key cryptox.Bytes, bs cryptox.Bytes) (cryptox.Bytes, error) {
	return hash(sha512.New384, key, bs)
}

// SHA512 uses hmac-sha512 to hash bs and returns an error if failed.
func SHA512(key cryptox.Bytes, bs cryptox.Bytes) (cryptox.Bytes, error) {
	return hash(sha512.New, key, bs)
}
