// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto/rsa"

	"github.com/FishGoddess/cryptox"
)

// PrivateKey is the private key of rsa.
type PrivateKey struct {
	key *rsa.PrivateKey
	bs  cryptox.Bytes
}

// newPrivateKey returns a private key.
func newPrivateKey(key *rsa.PrivateKey, bs cryptox.Bytes) PrivateKey {
	return PrivateKey{key: key, bs: bs}
}

// Key returns the key of pk.
func (pk PrivateKey) Key() *rsa.PrivateKey {
	return pk.key
}

// Bytes returns the bytes of pk.
func (pk PrivateKey) Bytes() cryptox.Bytes {
	return pk.bs
}

// EqualsTo returns if pk equals to privateKey.
func (pk PrivateKey) EqualsTo(privateKey PrivateKey) bool {
	return pk.key.Equal(privateKey.key)
}

// String returns the formatted string of pk.
func (pk PrivateKey) String() string {
	return pk.bs.String()
}
