// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

var (
	_ Hash = MD5
	_ Hash = SHA1
	_ Hash = SHA224
	_ Hash = SHA256
	_ Hash = SHA384
	_ Hash = SHA512
)

// Hash is a function returning hash.Hash.
type Hash func() hash.Hash

// MD5 returns md5 hash.
func MD5() hash.Hash {
	return md5.New()
}

// SHA1 returns sha1 hash.
func SHA1() hash.Hash {
	return sha1.New()
}

// SHA224 returns sha224 hash.
func SHA224() hash.Hash {
	return sha256.New224()
}

// SHA256 returns sha256 hash.
func SHA256() hash.Hash {
	return sha256.New()
}

// SHA384 returns sha384 hash.
func SHA384() hash.Hash {
	return sha512.New384()
}

// SHA512 returns sha512 hash.
func SHA512() hash.Hash {
	return sha512.New()
}

// Hasher hashes data with inside hash.
type Hasher struct {
	hash hash.Hash
}

// NewHasher returns a new hasher.
func NewHasher(h Hash) Hasher {
	return Hasher{hash: h()}
}

// Hash hashes data to bytes.
// Although it has an error in returning values, it should be nil forever.
func (h Hasher) Hash(data Bytes) (Bytes, error) {
	n, err := h.hash.Write(data)
	if err != nil {
		return nil, err
	}

	if n != len(data) {
		return nil, fmt.Errorf("cryptox.Hash: n %d != len(data) %d", n, len(data))
	}

	return h.hash.Sum(nil), nil
}
