// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package ed25519

import "crypto/ed25519"

type PrivateKey struct {
	key ed25519.PrivateKey
}

// Sign signs data.
func (pk PrivateKey) Sign(data []byte, opts ...Option) []byte {
	conf := newConfig().Apply(opts...)
	sign := ed25519.Sign(pk.key, data)
	sign = conf.encoding.Encode(sign)
	return sign
}

type PublicKey struct {
	key ed25519.PublicKey
}

// Verify verifies data with sign.
func (pk PublicKey) Verify(data []byte, sign []byte, opts ...Option) error {
	conf := newConfig().Apply(opts...)
	verifyOpts := &ed25519.Options{Hash: conf.cryptoHash, Context: conf.context}

	sign, err := conf.encoding.Decode(sign)
	if err != nil {
		return err
	}

	return ed25519.VerifyWithOptions(pk.key, data, sign, verifyOpts)
}
