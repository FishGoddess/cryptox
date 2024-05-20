// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto/rsa"

	"github.com/FishGoddess/cryptox"
)

// PrivateKey is the private key of rsa.
type PrivateKey struct {
	key      *rsa.PrivateKey
	keyBytes cryptox.Bytes
}

// newPrivateKey returns a private key.
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

// EqualsTo returns if pk equals to privateKey.
func (pk PrivateKey) EqualsTo(privateKey PrivateKey) bool {
	return pk.key.Equal(privateKey.key)
}

// String returns the formatted string of pk.
func (pk PrivateKey) String() string {
	return pk.keyBytes.String()
}

// DecryptPKCS1v15 decrypts msg with pkcs1 v15.
func (pk PrivateKey) DecryptPKCS1v15(msg cryptox.Bytes, opts ...Option) (cryptox.Bytes, error) {
	cfg := fromOptions(opts)
	return rsa.DecryptPKCS1v15(cfg.random, pk.key, msg)
}

// DecryptPKCS1v15SessionKey decrypts msg using a session key with pkcs1 v15.
func (pk PrivateKey) DecryptPKCS1v15SessionKey(msg cryptox.Bytes, sessionKey cryptox.Bytes, opts ...Option) error {
	cfg := fromOptions(opts)
	return rsa.DecryptPKCS1v15SessionKey(cfg.random, pk.key, msg, sessionKey)
}

// DecryptOAEP decrypts msg with oaep.
func (pk PrivateKey) DecryptOAEP(msg cryptox.Bytes, label cryptox.Bytes, opts ...Option) (cryptox.Bytes, error) {
	cfg := fromOptions(opts)
	return rsa.DecryptOAEP(cfg.hash, cfg.random, pk.key, msg, label)
}

// SignPKCS1v15 signs hashed data with pkcs1 v15.
func (pk PrivateKey) SignPKCS1v15(hashed cryptox.Bytes, opts ...Option) (cryptox.Bytes, error) {
	cfg := fromOptions(opts)
	return rsa.SignPKCS1v15(cfg.random, pk.key, cfg.cryptoHash, hashed)
}

// SignPSS signs digest data with pss.
func (pk PrivateKey) SignPSS(digest cryptox.Bytes, saltLength int, opts ...Option) (cryptox.Bytes, error) {
	cfg := fromOptions(opts)

	pssOpts := &rsa.PSSOptions{
		Hash:       cfg.cryptoHash,
		SaltLength: saltLength,
	}

	return rsa.SignPSS(cfg.random, pk.key, cfg.cryptoHash, digest, pssOpts)
}
