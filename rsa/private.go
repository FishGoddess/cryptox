// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto/rsa"

	"github.com/FishGoddess/cryptox"
)

type PrivateKey struct {
	key *rsa.PrivateKey
	bs  cryptox.Bytes
}

func newPrivateKey(key *rsa.PrivateKey, bs cryptox.Bytes) PrivateKey {
	return PrivateKey{key: key, bs: bs}
}

func (pk PrivateKey) Key() *rsa.PrivateKey {
	return pk.key
}

func (pk PrivateKey) Encoded() cryptox.Bytes {
	return pk.bs
}

func (pk PrivateKey) EqualsTo(privateKey PrivateKey) bool {
	return pk.key.Equal(privateKey)
}

func (pk PrivateKey) String() string {
	return pk.bs.String()
}
