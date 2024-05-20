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

// KeyConfig stores all configurations of key.
type KeyConfig struct {
	privateKeyEncoder PrivateKeyEncoder
	privateKeyDecoder PrivateKeyDecoder
	publicKeyEncoder  PublicKeyEncoder
	publicKeyDecoder  PublicKeyDecoder
}

// fromKeyOptions returns a key config constructed from key options.
func fromKeyOptions(opts []KeyOption) *KeyConfig {
	cfg := &KeyConfig{
		privateKeyEncoder: X509.PKCS1PrivateKeyEncoder,
		privateKeyDecoder: X509.PKCS1PrivateKeyDecoder,
		publicKeyEncoder:  X509.PKIXPublicKeyEncoder,
		publicKeyDecoder:  X509.PKIXPublicKeyDecoder,
	}

	for _, opt := range opts {
		opt.ApplyTo(cfg)
	}

	return cfg
}

// KeyOption is an option for key config.
type KeyOption func(cfg *KeyConfig)

// ApplyTo applies key option to key config.
func (ko KeyOption) ApplyTo(cfg *KeyConfig) {
	ko(cfg)
}

// WithPrivateKeyEncoder sets private key encoder to cfg.
func WithPrivateKeyEncoder(encoder PrivateKeyEncoder) KeyOption {
	return func(cfg *KeyConfig) {
		cfg.privateKeyEncoder = encoder
	}
}

// WithPrivateKeyDecoder sets private key decoder to cfg.
func WithPrivateKeyDecoder(decoder PrivateKeyDecoder) KeyOption {
	return func(cfg *KeyConfig) {
		cfg.privateKeyDecoder = decoder
	}
}

// WithPublicKeyEncoder sets public key encoder to cfg.
func WithPublicKeyEncoder(encoder PublicKeyEncoder) KeyOption {
	return func(cfg *KeyConfig) {
		cfg.publicKeyEncoder = encoder
	}
}

// WithPublicKeyDecoder sets public key decoder to cfg.
func WithPublicKeyDecoder(decoder PublicKeyDecoder) KeyOption {
	return func(cfg *KeyConfig) {
		cfg.publicKeyDecoder = decoder
	}
}

// Config stores all configurations used by encrypting/decrypting/signing/verifying.
type Config struct {
	random     io.Reader
	hash       hash.Hash
	cryptoHash crypto.Hash
}

// fromOptions returns a config constructed from options.
func fromOptions(opts []Option) *Config {
	cfg := &Config{
		random:     rand.Reader,
		hash:       sha256.New(),
		cryptoHash: crypto.SHA256,
	}

	for _, opt := range opts {
		opt.ApplyTo(cfg)
	}

	return cfg
}

// Option is an option for config.
type Option func(cfg *Config)

// ApplyTo applies option to config.
func (o Option) ApplyTo(cfg *Config) {
	o(cfg)
}

// WithRandom sets random to cfg.
func WithRandom(random io.Reader) Option {
	return func(cfg *Config) {
		cfg.random = random
	}
}

// WithHash sets hash to cfg.
func WithHash(hash hash.Hash) Option {
	return func(cfg *Config) {
		cfg.hash = hash
	}
}

// WithCryptoHash sets crypto hash to cfg.
func WithCryptoHash(hash crypto.Hash) Option {
	return func(cfg *Config) {
		cfg.cryptoHash = hash
	}
}
