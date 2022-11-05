// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto/rsa"

	"github.com/FishGoddess/cryptox"
)

type PublicKey struct {
	key *rsa.PublicKey
	bs  cryptox.Bytes
}

func newPublicKey(key *rsa.PublicKey, bs cryptox.Bytes) PublicKey {
	return PublicKey{key: key, bs: bs}
}

func (pk PublicKey) Key() *rsa.PublicKey {
	return pk.key
}

func (pk PublicKey) Encoded() cryptox.Bytes {
	return pk.bs
}

func (pk PublicKey) EqualsTo(publicKey PublicKey) bool {
	return pk.key.Equal(publicKey.key)
}

func (pk PublicKey) String() string {
	return pk.bs.String()
}
