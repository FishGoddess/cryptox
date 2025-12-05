// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto/rsa"
	"fmt"
)

type PrivateKey struct {
	key *rsa.PrivateKey
}

// DecryptPKCS1v15 decrypts data with pkcs1 v15.
func (pk PrivateKey) DecryptPKCS1v15(data []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	data, err := conf.encoding.Decode(data)
	if err != nil {
		return nil, err
	}

	return rsa.DecryptPKCS1v15(conf.random, pk.key, data)
}

// DecryptPKCS1v15SessionKey decrypts data using a session key with pkcs1 v15.
func (pk PrivateKey) DecryptPKCS1v15SessionKey(data []byte, sessionKey []byte, opts ...Option) error {
	conf := newConfig().Apply(opts...)

	data, err := conf.encoding.Decode(data)
	if err != nil {
		return err
	}

	return rsa.DecryptPKCS1v15SessionKey(conf.random, pk.key, data, sessionKey)
}

// DecryptOAEP decrypts data with oaep.
func (pk PrivateKey) DecryptOAEP(data []byte, label []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	data, err := conf.encoding.Decode(data)
	if err != nil {
		return nil, err
	}

	return rsa.DecryptOAEP(conf.hash, conf.random, pk.key, data, label)
}

// SignPKCS1v15 signs hashed with pkcs1 v15.
func (pk PrivateKey) SignPKCS1v15(hashed []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	sign, err := rsa.SignPKCS1v15(conf.random, pk.key, conf.cryptoHash, hashed)
	if err != nil {
		return nil, err
	}

	sign = conf.encoding.Encode(sign)
	return sign, nil
}

// SignPSS signs digest with pss.
func (pk PrivateKey) SignPSS(digest []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	if !conf.cryptoHash.Available() {
		return nil, fmt.Errorf("cryptox/rsa: crypto hash %+v isn't available", conf.cryptoHash)
	}

	pssOpts := &rsa.PSSOptions{Hash: conf.cryptoHash, SaltLength: conf.saltLength}

	sign, err := rsa.SignPSS(conf.random, pk.key, conf.cryptoHash, digest, pssOpts)
	if err != nil {
		return nil, err
	}

	sign = conf.encoding.Encode(sign)
	return sign, nil
}
