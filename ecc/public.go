// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package ecc

import (
	"crypto/ed25519"

	"github.com/FishGoddess/cryptox"
)

type PublicKey struct {
	key ed25519.PublicKey
}

func newPublicKey(key ed25519.PublicKey) PublicKey {
	return PublicKey{key: key}
}

// Key returns the key of pk.
func (pk PublicKey) Key() ed25519.PublicKey {
	return pk.key
}

// Bytes returns the bytes of pk.
func (pk PublicKey) Bytes() cryptox.Bytes {
	return cryptox.Bytes(pk.key)
}

// String returns the string of pk.
func (pk PublicKey) String() string {
	return string(pk.key)
}

// EqualsTo returns if pk equals to privateKey.
func (pk PublicKey) EqualsTo(publicKey PublicKey) bool {
	return pk.key.Equal(publicKey.key)
}
