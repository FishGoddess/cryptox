// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto/rsa"

	"github.com/FishGoddess/cryptox/bytes/encoding"
)

type PrivateKey struct {
	key *rsa.PrivateKey
}

// DecryptPKCS1v15 decrypts bs with pkcs1 v15.
func (pk PrivateKey) DecryptPKCS1v15(bs []byte, encoding encoding.Encoding, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	bs, err := encoding.Decode(bs)
	if err != nil {
		return nil, err
	}

	return rsa.DecryptPKCS1v15(conf.random, pk.key, bs)
}

// DecryptPKCS1v15SessionKey decrypts bs using a session key with pkcs1 v15.
func (pk PrivateKey) DecryptPKCS1v15SessionKey(bs []byte, sessionKey []byte, encoding encoding.Encoding, opts ...Option) error {
	conf := newConfig().Apply(opts...)

	bs, err := encoding.Decode(bs)
	if err != nil {
		return err
	}

	return rsa.DecryptPKCS1v15SessionKey(conf.random, pk.key, bs, sessionKey)
}

// DecryptOAEP decrypts bs with oaep.
func (pk PrivateKey) DecryptOAEP(bs []byte, label []byte, encoding encoding.Encoding, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	bs, err := encoding.Decode(bs)
	if err != nil {
		return nil, err
	}

	return rsa.DecryptOAEP(conf.hash, conf.random, pk.key, bs, label)
}

// SignPKCS1v15 signs hashed with pkcs1 v15.
func (pk PrivateKey) SignPKCS1v15(hashed []byte, encoding encoding.Encoding, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	sign, err := rsa.SignPKCS1v15(conf.random, pk.key, conf.cryptoHash, hashed)
	if err != nil {
		return nil, err
	}

	sign = encoding.Encode(sign)
	return sign, nil
}

// SignPSS signs digest with pss.
func (pk PrivateKey) SignPSS(digest []byte, saltLength int, encoding encoding.Encoding, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)
	pssOpts := &rsa.PSSOptions{Hash: conf.cryptoHash, SaltLength: saltLength}

	sign, err := rsa.SignPSS(conf.random, pk.key, conf.cryptoHash, digest, pssOpts)
	if err != nil {
		return nil, err
	}

	sign = encoding.Encode(sign)
	return sign, nil
}
