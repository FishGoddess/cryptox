// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto"
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

func (r *RSA) EncryptPKCS1v15(data cryptox.Bytes) (cryptox.Bytes, error) {
	return rsa.EncryptPKCS1v15(r.random, r.publicKey, data)
}

func (r *RSA) DecryptPKCS1v15(data cryptox.Bytes) (cryptox.Bytes, error) {
	return rsa.DecryptPKCS1v15(r.random, r.privateKey, data)
}

func (r *RSA) DecryptPKCS1v15SessionKey(data cryptox.Bytes, key cryptox.Bytes) error {
	return rsa.DecryptPKCS1v15SessionKey(r.random, r.privateKey, data, key)
}

func (r *RSA) EncryptOAEP(hash hash.Hash, data cryptox.Bytes, label cryptox.Bytes) (cryptox.Bytes, error) {
	return rsa.EncryptOAEP(hash, r.random, r.publicKey, data, label)
}

func (r *RSA) DecryptOAEP(hash hash.Hash, data cryptox.Bytes, label cryptox.Bytes) (cryptox.Bytes, error) {
	return rsa.DecryptOAEP(hash, r.random, r.privateKey, data, label)
}

func (r *RSA) SignPKCS1v15(hash crypto.Hash, hashed cryptox.Bytes) (cryptox.Bytes, error) {
	return rsa.SignPKCS1v15(r.random, r.privateKey, hash, hashed)
}

func (r *RSA) VerifyPKCS1v15(hash crypto.Hash, hashed cryptox.Bytes, signature cryptox.Bytes) error {
	return rsa.VerifyPKCS1v15(r.publicKey, hash, hashed, signature)
}

func (r *RSA) SignPSS(hash crypto.Hash, saltLength int, digest cryptox.Bytes) (cryptox.Bytes, error) {
	opts := &rsa.PSSOptions{SaltLength: saltLength, Hash: hash}
	return rsa.SignPSS(r.random, r.privateKey, hash, digest, opts)
}

func (r *RSA) VerifyPSS(hash crypto.Hash, saltLength int, digest cryptox.Bytes, signature cryptox.Bytes) error {
	opts := &rsa.PSSOptions{SaltLength: saltLength, Hash: hash}
	return rsa.VerifyPSS(r.publicKey, hash, digest, signature, opts)
}
