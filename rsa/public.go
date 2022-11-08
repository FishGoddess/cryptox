// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto/rsa"

	"github.com/FishGoddess/cryptox"
)

// PublicKey is the public key of rsa.
type PublicKey struct {
	key      *rsa.PublicKey
	keyBytes cryptox.Bytes
}

// newPublicKey returns a public key.
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

// EqualsTo returns if pk equals to privateKey.
func (pk PublicKey) EqualsTo(publicKey PublicKey) bool {
	return pk.key.Equal(publicKey.key)
}

// String returns the formatted string of pk.
func (pk PublicKey) String() string {
	return pk.keyBytes.String()
}

// EncryptPKCS1v15 encrypts msg with pkcs1 v15.
func (pk PublicKey) EncryptPKCS1v15(msg cryptox.Bytes, opts ...Option) (cryptox.Bytes, error) {
	cfg := fromOptions(opts...)
	return rsa.EncryptPKCS1v15(cfg.random, pk.key, msg)
}

// EncryptOAEP encrypts msg with oaep.
func (pk PublicKey) EncryptOAEP(msg cryptox.Bytes, label cryptox.Bytes, opts ...Option) (cryptox.Bytes, error) {
	cfg := fromOptions(opts...)
	return rsa.EncryptOAEP(cfg.hash, cfg.random, pk.key, msg, label)
}

// VerifyPKCS1v15 verifies signature with pkcs1 v15.
func (pk PublicKey) VerifyPKCS1v15(hashed cryptox.Bytes, signature cryptox.Bytes, opts ...Option) error {
	cfg := fromOptions(opts...)
	return rsa.VerifyPKCS1v15(pk.key, cfg.cryptoHash, hashed, signature)
}

// VerifyPSS verifies signature with pss.
func (pk PublicKey) VerifyPSS(digest cryptox.Bytes, signature cryptox.Bytes, saltLength int, opts ...Option) error {
	cfg := fromOptions(opts...)

	pssOpts := &rsa.PSSOptions{
		Hash:       cfg.cryptoHash,
		SaltLength: saltLength,
	}

	return rsa.VerifyPSS(pk.key, cfg.cryptoHash, digest, signature, pssOpts)
}
