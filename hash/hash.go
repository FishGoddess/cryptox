// Copyright 2023 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hash

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	stdhash "hash"

	"github.com/FishGoddess/cryptox"
)

func hash(h stdhash.Hash, bs cryptox.Bytes) (cryptox.Bytes, error) {
	n, err := h.Write(bs)
	if err != nil {
		return nil, err
	}

	if n != len(bs) {
		return nil, fmt.Errorf("hash: hashed n %d != len(bs) %d", n, len(bs))
	}

	return h.Sum(nil), nil
}

// MD5 uses md5 to hash bs and returns an error if failed.
func MD5(bs cryptox.Bytes) (cryptox.Bytes, error) {
	return hash(md5.New(), bs)
}

// SHA1 uses sha1 to hash bs and returns an error if failed.
func SHA1(bs cryptox.Bytes) (cryptox.Bytes, error) {
	return hash(sha1.New(), bs)
}

// SHA224 uses sha224 to hash bs and returns an error if failed.
func SHA224(bs cryptox.Bytes) (cryptox.Bytes, error) {
	return hash(sha256.New224(), bs)
}

// SHA256 uses sha256 to hash bs and returns an error if failed.
func SHA256(bs cryptox.Bytes) (cryptox.Bytes, error) {
	return hash(sha256.New(), bs)
}

// SHA384 uses sha384 to hash bs and returns an error if failed.
func SHA384(bs cryptox.Bytes) (cryptox.Bytes, error) {
	return hash(sha512.New384(), bs)
}

// SHA512 uses sha512 to hash bs and returns an error if failed.
func SHA512(bs cryptox.Bytes) (cryptox.Bytes, error) {
	return hash(sha512.New(), bs)
}
