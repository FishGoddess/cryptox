// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto/rsa"

	"github.com/FishGoddess/cryptox"
)

// PublicKey is the public key of rsa.
type PublicKey struct {
	key      *rsa.PublicKey
	keyBytes cryptox.Bytes
}

// newPublicKey returns a public key.
func newPublicKey(key *rsa.PublicKey, keyBytes cryptox.Bytes) PublicKey {
	return PublicKey{key: key, keyBytes: keyBytes}
}

// Key returns the key of pk.
func (pk PublicKey) Key() *rsa.PublicKey {
	return pk.key
}

// Bytes returns the bytes of pk.
func (pk PublicKey) Bytes() cryptox.Bytes {
	return pk.keyBytes
}

// EqualsTo returns if pk equals to privateKey.
func (pk PublicKey) EqualsTo(publicKey PublicKey) bool {
	return pk.key.Equal(publicKey.key)
}

// String returns the formatted string of pk.
func (pk PublicKey) String() string {
	return pk.keyBytes.String()
}
