// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

// KeyConfig stores all configurations of key.
type KeyConfig struct {
	privateKeyEncoder PrivateKeyEncoder
	publicKeyEncoder  PublicKeyEncoder
	privateKeyDecoder PrivateKeyDecoder
	publicKeyDecoder  PublicKeyDecoder
}

// fromKeyOptions returns a key config constructed from key options.
func fromKeyOptions(opts ...KeyOption) *KeyConfig {
	cfg := &KeyConfig{
		privateKeyEncoder: X509.PKCS1PrivateKeyEncoder,
		publicKeyEncoder:  X509.PKIXPublicKeyEncoder,
		privateKeyDecoder: X509.PKCS1PrivateKeyDecoder,
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
func (ko KeyOption) ApplyTo(opts *KeyConfig) {
	ko(opts)
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
