// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package ecc

import (
	"crypto/ed25519"

	"github.com/FishGoddess/cryptox"
)

type PrivateKey struct {
	key ed25519.PrivateKey
}

func newPrivateKey(key ed25519.PrivateKey) PrivateKey {
	return PrivateKey{key: key}
}

// Key returns the key of pk.
func (pk PrivateKey) Key() ed25519.PrivateKey {
	return pk.key
}

// Bytes returns the bytes of pk.
func (pk PrivateKey) Bytes() cryptox.Bytes {
	return cryptox.Bytes(pk.key)
}

// String returns the string of pk.
func (pk PrivateKey) String() string {
	return string(pk.key)
}

// EqualsTo returns if pk equals to privateKey.
func (pk PrivateKey) EqualsTo(privateKey PrivateKey) bool {
	return pk.key.Equal(privateKey.key)
}
