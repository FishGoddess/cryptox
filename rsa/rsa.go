// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"hash"
	"io"

	"github.com/FishGoddess/cryptox"
)

type OAEP struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	hash       hash.Hash
	random     io.Reader
}

func NewOAEP(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, opts ...OAEPOption) *OAEP {
	oaep := &OAEP{
		privateKey: privateKey,
		publicKey:  publicKey,
		hash:       cryptox.SHA256(),
		random:     rand.Reader,
	}

	for _, opt := range opts {
		opt.ApplyTo(oaep)
	}

	return oaep
}

func (o *OAEP) EncryptWithPublicKey(data cryptox.Bytes, label cryptox.Bytes) (cryptox.Bytes, error) {
	return rsa.EncryptOAEP(o.hash, o.random, o.publicKey, data, label)
}

func (o *OAEP) DecryptWithPrivateKey(data cryptox.Bytes, label cryptox.Bytes) (cryptox.Bytes, error) {
	return rsa.DecryptOAEP(o.hash, o.random, o.privateKey, data, label)
}
