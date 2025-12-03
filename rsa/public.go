// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto/rsa"

	"github.com/FishGoddess/cryptox/bytes/encoding"
)

type PublicKey struct {
	key *rsa.PublicKey
}

// EncryptPKCS1v15 encrypts bs with pkcs1 v15.
func (pk PublicKey) EncryptPKCS1v15(bs []byte, encoding encoding.Encoding, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	bs, err := rsa.EncryptPKCS1v15(conf.random, pk.key, bs)
	if err != nil {
		return nil, err
	}

	bs = encoding.Encode(bs)
	return bs, nil
}

// EncryptOAEP encrypts bs with oaep.
func (pk PublicKey) EncryptOAEP(bs []byte, label []byte, encoding encoding.Encoding, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	bs, err := rsa.EncryptOAEP(conf.hash, conf.random, pk.key, bs, label)
	if err != nil {
		return nil, err
	}

	bs = encoding.Encode(bs)
	return bs, nil
}

// VerifyPKCS1v15 verifies hashed with pkcs1 v15.
func (pk PublicKey) VerifyPKCS1v15(hashed []byte, sign []byte, encoding encoding.Encoding, opts ...Option) error {
	conf := newConfig().Apply(opts...)

	sign, err := encoding.Decode(sign)
	if err != nil {
		return err
	}

	return rsa.VerifyPKCS1v15(pk.key, conf.cryptoHash, hashed, sign)
}

// VerifyPSS verifies digest with pss.
func (pk PublicKey) VerifyPSS(digest []byte, sign []byte, saltLength int, encoding encoding.Encoding, opts ...Option) error {
	conf := newConfig().Apply(opts...)
	pssOpts := &rsa.PSSOptions{Hash: conf.cryptoHash, SaltLength: saltLength}

	sign, err := encoding.Decode(sign)
	if err != nil {
		return err
	}

	return rsa.VerifyPSS(pk.key, conf.cryptoHash, digest, sign, pssOpts)
}
