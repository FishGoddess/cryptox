// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto/rsa"
)

type PublicKey struct {
	key *rsa.PublicKey
}

// EncryptPKCS1v15 encrypts data with pkcs1 v15.
func (pk PublicKey) EncryptPKCS1v15(data []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	data, err := rsa.EncryptPKCS1v15(conf.random, pk.key, data)
	if err != nil {
		return nil, err
	}

	data = conf.encoding.Encode(data)
	return data, nil
}

// EncryptOAEP encrypts data with oaep.
func (pk PublicKey) EncryptOAEP(data []byte, label []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	data, err := rsa.EncryptOAEP(conf.hash, conf.random, pk.key, data, label)
	if err != nil {
		return nil, err
	}

	data = conf.encoding.Encode(data)
	return data, nil
}

// VerifyPKCS1v15 verifies hashed with pkcs1 v15.
func (pk PublicKey) VerifyPKCS1v15(hashed []byte, sign []byte, opts ...Option) error {
	conf := newConfig().Apply(opts...)

	sign, err := conf.encoding.Decode(sign)
	if err != nil {
		return err
	}

	return rsa.VerifyPKCS1v15(pk.key, conf.cryptoHash, hashed, sign)
}

// VerifyPSS verifies digest with pss.
func (pk PublicKey) VerifyPSS(digest []byte, sign []byte, saltLength int, opts ...Option) error {
	conf := newConfig().Apply(opts...)
	pssOpts := &rsa.PSSOptions{Hash: conf.cryptoHash, SaltLength: saltLength}

	sign, err := conf.encoding.Decode(sign)
	if err != nil {
		return err
	}

	return rsa.VerifyPSS(pk.key, conf.cryptoHash, digest, sign, pssOpts)
}
