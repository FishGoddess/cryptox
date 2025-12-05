// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package ed25519

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"io"

	"github.com/FishGoddess/cryptox/bytes/encoding"
	"github.com/FishGoddess/cryptox/x509"
)

type KeyConfig struct {
	seed             []byte
	random           io.Reader
	encodePrivateKey func(key ed25519.PrivateKey) ([]byte, error)
	encodePublicKey  func(key ed25519.PublicKey) ([]byte, error)
	decodePrivateKey func(data []byte) (ed25519.PrivateKey, error)
	decodePublicKey  func(data []byte) (ed25519.PublicKey, error)
}

func newKeyConfig() *KeyConfig {
	conf := &KeyConfig{
		seed:             nil,
		random:           rand.Reader,
		encodePrivateKey: x509.EncodePrivateKeyPKCS8[ed25519.PrivateKey],
		encodePublicKey:  x509.EncodePublicKeyPKIX[ed25519.PublicKey],
		decodePrivateKey: x509.DecodePrivateKeyPKCS8[ed25519.PrivateKey],
		decodePublicKey:  x509.DecodePublicKeyPKIX[ed25519.PublicKey],
	}

	return conf
}

func (kc *KeyConfig) Apply(opts ...KeyOption) *KeyConfig {
	for _, opt := range opts {
		opt(kc)
	}

	return kc
}

type KeyOption func(conf *KeyConfig)

// WithKeySeed sets seed to key config.
func WithKeySeed(seed []byte) KeyOption {
	return func(conf *KeyConfig) {
		conf.seed = seed
	}
}

// WithKeyRandom sets random to key config.
func WithKeyRandom(random io.Reader) KeyOption {
	return func(conf *KeyConfig) {
		conf.random = random
	}
}

// WithKeyEncodePrivate sets encode to key config.
func WithKeyEncodePrivate(encode func(key ed25519.PrivateKey) ([]byte, error)) KeyOption {
	return func(conf *KeyConfig) {
		conf.encodePrivateKey = encode
	}
}

// WithKeyEncodePublic sets encode to key config.
func WithKeyEncodePublic(encode func(key ed25519.PublicKey) ([]byte, error)) KeyOption {
	return func(conf *KeyConfig) {
		conf.encodePublicKey = encode
	}
}

// WithKeyDecodePrivate sets decode to key config.
func WithKeyDecodePrivate(decode func(data []byte) (ed25519.PrivateKey, error)) KeyOption {
	return func(conf *KeyConfig) {
		conf.decodePrivateKey = decode
	}
}

// WithKeyDecodePublic sets decode to key config.
func WithKeyDecodePublic(decode func(data []byte) (ed25519.PublicKey, error)) KeyOption {
	return func(conf *KeyConfig) {
		conf.decodePublicKey = decode
	}
}

type Config struct {
	encoding   encoding.Encoding
	cryptoHash crypto.Hash
	context    string
}

func newConfig() *Config {
	conf := &Config{
		encoding:   encoding.None{},
		cryptoHash: crypto.Hash(0),
		context:    "",
	}

	return conf
}

func (c *Config) Apply(opts ...Option) *Config {
	for _, opt := range opts {
		opt(c)
	}

	return c
}

type Option func(conf *Config)

// WithHex sets hex encoding to config.
func WithHex() Option {
	return func(conf *Config) {
		conf.encoding = encoding.Hex{}
	}
}

// WithBase64 sets base64 encoding to config.
func WithBase64() Option {
	return func(conf *Config) {
		conf.encoding = encoding.Base64{}
	}
}

// WithCryptoHash sets crypto hash to config.
func WithCryptoHash(hash crypto.Hash) Option {
	return func(conf *Config) {
		conf.cryptoHash = hash
	}
}

// WithContext sets context to config.
func WithContext(context string) Option {
	return func(conf *Config) {
		conf.context = context
	}
}
