// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto/rsa"

	"github.com/FishGoddess/cryptox"
)

type PublicKey struct {
	key      *rsa.PublicKey
	keyBytes cryptox.Bytes
}

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

// String returns the string of pk.
func (pk PublicKey) String() string {
	return string(pk.keyBytes)
}

// EqualsTo returns if pk equals to privateKey.
func (pk PublicKey) EqualsTo(publicKey PublicKey) bool {
	return pk.key.Equal(publicKey.key)
}

// EncryptPKCS1v15 encrypts msg with pkcs1 v15.
func (pk PublicKey) EncryptPKCS1v15(msg cryptox.Bytes, opts ...Option) (cryptox.Bytes, error) {
	conf := newConfig(opts)
	return rsa.EncryptPKCS1v15(conf.random, pk.key, msg)
}

// EncryptOAEP encrypts msg with oaep.
func (pk PublicKey) EncryptOAEP(msg cryptox.Bytes, label cryptox.Bytes, opts ...Option) (cryptox.Bytes, error) {
	conf := newConfig(opts)
	return rsa.EncryptOAEP(conf.hash, conf.random, pk.key, msg, label)
}

// VerifyPKCS1v15 verifies signature with pkcs1 v15.
func (pk PublicKey) VerifyPKCS1v15(hashed cryptox.Bytes, signature cryptox.Bytes, opts ...Option) error {
	conf := newConfig(opts)
	return rsa.VerifyPKCS1v15(pk.key, conf.cryptoHash, hashed, signature)
}

// VerifyPSS verifies signature with pss.
func (pk PublicKey) VerifyPSS(digest cryptox.Bytes, signature cryptox.Bytes, saltLength int, opts ...Option) error {
	conf := newConfig(opts)

	pssOpts := &rsa.PSSOptions{
		Hash:       conf.cryptoHash,
		SaltLength: saltLength,
	}

	return rsa.VerifyPSS(pk.key, conf.cryptoHash, digest, signature, pssOpts)
}
