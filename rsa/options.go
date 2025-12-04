// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"hash"
	"io"

	"github.com/FishGoddess/cryptox/bytes/encoding"
	"github.com/FishGoddess/cryptox/x509"
)

type KeyConfig struct {
	random           io.Reader
	encodePrivateKey func(key *rsa.PrivateKey) ([]byte, error)
	encodePublicKey  func(key *rsa.PublicKey) ([]byte, error)
	decodePrivateKey func(bs []byte) (*rsa.PrivateKey, error)
	decodePublicKey  func(bs []byte) (*rsa.PublicKey, error)
}

func newKeyConfig() *KeyConfig {
	conf := &KeyConfig{
		random:           rand.Reader,
		encodePrivateKey: x509.EncodePrivateKeyPKCS8[*rsa.PrivateKey],
		encodePublicKey:  x509.EncodePublicKeyPKIX[*rsa.PublicKey],
		decodePrivateKey: x509.DecodePrivateKeyPKCS8[*rsa.PrivateKey],
		decodePublicKey:  x509.DecodePublicKeyPKIX[*rsa.PublicKey],
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

// WithKeyRandom sets random to key config.
func WithKeyRandom(random io.Reader) KeyOption {
	return func(conf *KeyConfig) {
		conf.random = random
	}
}

// WithKeyEncodePrivate sets encode to key config.
func WithKeyEncodePrivate(encode func(key *rsa.PrivateKey) ([]byte, error)) KeyOption {
	return func(conf *KeyConfig) {
		conf.encodePrivateKey = encode
	}
}

// WithKeyEncodePublic sets encode to key config.
func WithKeyEncodePublic(encode func(key *rsa.PublicKey) ([]byte, error)) KeyOption {
	return func(conf *KeyConfig) {
		conf.encodePublicKey = encode
	}
}

// WithKeyDecodePrivate sets decode to key config.
func WithKeyDecodePrivate(decode func(bs []byte) (*rsa.PrivateKey, error)) KeyOption {
	return func(conf *KeyConfig) {
		conf.decodePrivateKey = decode
	}
}

// WithKeyDecodePublic sets decode to key config.
func WithKeyDecodePublic(decode func(bs []byte) (*rsa.PublicKey, error)) KeyOption {
	return func(conf *KeyConfig) {
		conf.decodePublicKey = decode
	}
}

type Config struct {
	encoding   encoding.Encoding
	random     io.Reader
	hash       hash.Hash
	cryptoHash crypto.Hash
}

func newConfig() *Config {
	conf := &Config{
		encoding:   encoding.None{},
		random:     rand.Reader,
		hash:       sha256.New(),
		cryptoHash: crypto.SHA256,
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

// WithRandom sets random to config.
func WithRandom(random io.Reader) Option {
	return func(conf *Config) {
		conf.random = random
	}
}

// WithHash sets hash to config.
func WithHash(hash hash.Hash) Option {
	return func(conf *Config) {
		conf.hash = hash
	}
}

// WithCryptoHash sets crypto hash to config.
func WithCryptoHash(hash crypto.Hash) Option {
	return func(conf *Config) {
		conf.cryptoHash = hash
	}
}
