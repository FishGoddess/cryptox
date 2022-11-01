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

type RSA struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	random     io.Reader
}

func New(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, opts ...Option) *RSA {
	oaep := &RSA{
		privateKey: privateKey,
		publicKey:  publicKey,
		random:     rand.Reader,
	}

	for _, opt := range opts {
		opt.ApplyTo(oaep)
	}

	return oaep
}

func (r *RSA) EncryptOAEP(hash hash.Hash, data cryptox.Bytes, label cryptox.Bytes) (cryptox.Bytes, error) {
	return rsa.EncryptOAEP(hash, r.random, r.publicKey, data, label)
}

func (r *RSA) DecryptOAEP(hash hash.Hash, data cryptox.Bytes, label cryptox.Bytes) (cryptox.Bytes, error) {
	return rsa.DecryptOAEP(hash, r.random, r.privateKey, data, label)
}
