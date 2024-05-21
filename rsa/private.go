// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto/rsa"

	"github.com/FishGoddess/cryptox"
)

type PrivateKey struct {
	key      *rsa.PrivateKey
	keyBytes cryptox.Bytes
}

func newPrivateKey(key *rsa.PrivateKey, keyBytes cryptox.Bytes) PrivateKey {
	return PrivateKey{key: key, keyBytes: keyBytes}
}

// Key returns the key of pk.
func (pk PrivateKey) Key() *rsa.PrivateKey {
	return pk.key
}

// Bytes returns the bytes of pk.
func (pk PrivateKey) Bytes() cryptox.Bytes {
	return pk.keyBytes
}

// String returns the string of pk.
func (pk PrivateKey) String() string {
	return string(pk.keyBytes)
}

// EqualsTo returns if pk equals to privateKey.
func (pk PrivateKey) EqualsTo(privateKey PrivateKey) bool {
	return pk.key.Equal(privateKey.key)
}

// DecryptPKCS1v15 decrypts msg with pkcs1 v15.
func (pk PrivateKey) DecryptPKCS1v15(msg cryptox.Bytes, opts ...Option) (cryptox.Bytes, error) {
	conf := newConfig(opts)
	return rsa.DecryptPKCS1v15(conf.random, pk.key, msg)
}

// DecryptPKCS1v15SessionKey decrypts msg using a session key with pkcs1 v15.
func (pk PrivateKey) DecryptPKCS1v15SessionKey(msg cryptox.Bytes, sessionKey cryptox.Bytes, opts ...Option) error {
	conf := newConfig(opts)
	return rsa.DecryptPKCS1v15SessionKey(conf.random, pk.key, msg, sessionKey)
}

// DecryptOAEP decrypts msg with oaep.
func (pk PrivateKey) DecryptOAEP(msg cryptox.Bytes, label cryptox.Bytes, opts ...Option) (cryptox.Bytes, error) {
	conf := newConfig(opts)
	return rsa.DecryptOAEP(conf.hash, conf.random, pk.key, msg, label)
}

// SignPKCS1v15 signs hashed data with pkcs1 v15.
func (pk PrivateKey) SignPKCS1v15(hashed cryptox.Bytes, opts ...Option) (cryptox.Bytes, error) {
	conf := newConfig(opts)
	return rsa.SignPKCS1v15(conf.random, pk.key, conf.cryptoHash, hashed)
}

// SignPSS signs digest data with pss.
func (pk PrivateKey) SignPSS(digest cryptox.Bytes, saltLength int, opts ...Option) (cryptox.Bytes, error) {
	conf := newConfig(opts)

	pssOpts := &rsa.PSSOptions{
		Hash:       conf.cryptoHash,
		SaltLength: saltLength,
	}

	return rsa.SignPSS(conf.random, pk.key, conf.cryptoHash, digest, pssOpts)
}
