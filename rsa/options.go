// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"hash"
	"io"
)

// GeneratorOption is a function for setting key generator.
type GeneratorOption func(generator *KeyGenerator)

// ApplyTo applies generator option to generator.
func (o GeneratorOption) ApplyTo(generator *KeyGenerator) {
	o(generator)
}

// WithGeneratePrivateKeyEncoder sets private key encoder to generator.
func WithGeneratePrivateKeyEncoder(encoder PrivateKeyEncoder) GeneratorOption {
	return func(generator *KeyGenerator) {
		generator.privateKeyEncoder = encoder
	}
}

// WithGeneratePrivateKeyDecoder sets private key decoder to generator.
func WithGeneratePrivateKeyDecoder(decoder PrivateKeyDecoder) GeneratorOption {
	return func(generator *KeyGenerator) {
		generator.privateKeyDecoder = decoder
	}
}

// WithGeneratePublicKeyEncoder sets public key encoder to generator.
func WithGeneratePublicKeyEncoder(encoder PublicKeyEncoder) GeneratorOption {
	return func(generator *KeyGenerator) {
		generator.publicKeyEncoder = encoder
	}
}

// LoaderOption is a function for setting key loader.
type LoaderOption func(loader *KeyLoader)

// ApplyTo applies key option to loader.
func (o LoaderOption) ApplyTo(loader *KeyLoader) {
	o(loader)
}

// WithLoadPrivateKeyDecoder sets private key decoder to loader.
func WithLoadPrivateKeyDecoder(decoder PrivateKeyDecoder) LoaderOption {
	return func(loader *KeyLoader) {
		loader.privateKeyDecoder = decoder
	}
}

// WithLoadPublicKeyDecoder sets public key decoder to loader.
func WithLoadPublicKeyDecoder(decoder PublicKeyDecoder) LoaderOption {
	return func(loader *KeyLoader) {
		loader.publicKeyDecoder = decoder
	}
}

// OAEPOption is a function for setting oaep.
type OAEPOption func(oaep *OAEP)

// ApplyTo applies oaep option to oaep.
func (oo OAEPOption) ApplyTo(oaep *OAEP) {
	oo(oaep)
}

func WithOAEPHash(hash hash.Hash) OAEPOption {
	return func(oaep *OAEP) {
		oaep.hash = hash
	}
}

func WithOAEPRandom(random io.Reader) OAEPOption {
	return func(oaep *OAEP) {
		oaep.random = random
	}
}
