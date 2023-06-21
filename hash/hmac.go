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

	"github.com/FishGoddess/cryptox"
)

// HMACPack packs some HMAC functions.
// You should use HMAC() directly.
type HMACPack struct {
	key cryptox.Bytes
}

// HMAC returns the HMACPack to use some HMAC functions.
func HMAC(key cryptox.Bytes) HMACPack {
	return HMACPack{
		key: key,
	}
}

func (hp HMACPack) hash(hashFunc func() stdhash.Hash, bs cryptox.Bytes) (cryptox.Bytes, error) {
	h := hmac.New(hashFunc, hp.key)

	n, err := h.Write(bs)
	if err != nil {
		return nil, err
	}

	if n != len(bs) {
		return nil, fmt.Errorf("hash: hashed n %d != len(bs) %d", n, len(bs))
	}

	return h.Sum(nil), nil
}

// MD5 uses hmac-md5 to hash bs and returns an error if failed.
func (hp HMACPack) MD5(bs cryptox.Bytes) (cryptox.Bytes, error) {
	return hp.hash(md5.New, bs)
}

// SHA1 uses hmac-sha1 to hash bs and returns an error if failed.
func (hp HMACPack) SHA1(bs cryptox.Bytes) (cryptox.Bytes, error) {
	return hp.hash(sha1.New, bs)
}

// SHA224 uses hmac-sha224 to hash bs and returns an error if failed.
func (hp HMACPack) SHA224(bs cryptox.Bytes) (cryptox.Bytes, error) {
	return hp.hash(sha256.New224, bs)
}

// SHA256 uses hmac-sha256 to hash bs and returns an error if failed.
func (hp HMACPack) SHA256(bs cryptox.Bytes) (cryptox.Bytes, error) {
	return hp.hash(sha256.New, bs)
}

// SHA384 uses hmac-sha384 to hash bs and returns an error if failed.
func (hp HMACPack) SHA384(bs cryptox.Bytes) (cryptox.Bytes, error) {
	return hp.hash(sha512.New384, bs)
}

// SHA512 uses hmac-sha512 to hash bs and returns an error if failed.
func (hp HMACPack) SHA512(bs cryptox.Bytes) (cryptox.Bytes, error) {
	return hp.hash(sha512.New, bs)
}
