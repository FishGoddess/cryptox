// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"hash"
	"io"
)

type KeyConfig struct {
	privateKeyEncoder PrivateKeyEncoder
	privateKeyDecoder PrivateKeyDecoder
	publicKeyEncoder  PublicKeyEncoder
	publicKeyDecoder  PublicKeyDecoder
}

func newKeyConfig(opts []KeyOption) *KeyConfig {
	conf := &KeyConfig{
		privateKeyEncoder: X509.PKCS1PrivateKeyEncoder,
		privateKeyDecoder: X509.PKCS1PrivateKeyDecoder,
		publicKeyEncoder:  X509.PKIXPublicKeyEncoder,
		publicKeyDecoder:  X509.PKIXPublicKeyDecoder,
	}

	for _, opt := range opts {
		opt.ApplyTo(conf)
	}

	return conf
}

type KeyOption func(conf *KeyConfig)

func (ko KeyOption) ApplyTo(conf *KeyConfig) {
	ko(conf)
}

// WithPrivateKeyEncoder sets private key encoder to conf.
func WithPrivateKeyEncoder(encoder PrivateKeyEncoder) KeyOption {
	return func(conf *KeyConfig) {
		conf.privateKeyEncoder = encoder
	}
}

// WithPrivateKeyDecoder sets private key decoder to conf.
func WithPrivateKeyDecoder(decoder PrivateKeyDecoder) KeyOption {
	return func(conf *KeyConfig) {
		conf.privateKeyDecoder = decoder
	}
}

// WithPublicKeyEncoder sets public key encoder to conf.
func WithPublicKeyEncoder(encoder PublicKeyEncoder) KeyOption {
	return func(conf *KeyConfig) {
		conf.publicKeyEncoder = encoder
	}
}

// WithPublicKeyDecoder sets public key decoder to conf.
func WithPublicKeyDecoder(decoder PublicKeyDecoder) KeyOption {
	return func(conf *KeyConfig) {
		conf.publicKeyDecoder = decoder
	}
}

type Config struct {
	random     io.Reader
	hash       hash.Hash
	cryptoHash crypto.Hash
}

func newConfig(opts []Option) *Config {
	conf := &Config{
		random:     rand.Reader,
		hash:       sha256.New(),
		cryptoHash: crypto.SHA256,
	}

	for _, opt := range opts {
		opt.ApplyTo(conf)
	}

	return conf
}

type Option func(conf *Config)

func (o Option) ApplyTo(conf *Config) {
	o(conf)
}

// WithRandom sets random to conf.
func WithRandom(random io.Reader) Option {
	return func(conf *Config) {
		conf.random = random
	}
}

// WithHash sets hash to conf.
func WithHash(hash hash.Hash) Option {
	return func(conf *Config) {
		conf.hash = hash
	}
}

// WithCryptoHash sets crypto hash to conf.
func WithCryptoHash(hash crypto.Hash) Option {
	return func(conf *Config) {
		conf.cryptoHash = hash
	}
}
