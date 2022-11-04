// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"io/ioutil"

	"github.com/FishGoddess/cryptox"
)

// KeyGenerator is a generator for generating rsa key including private and public.
type KeyGenerator struct {
	privateKeyEncoder PrivateKeyEncoder
	publicKeyEncoder  PublicKeyEncoder
	privateKeyDecoder PrivateKeyDecoder
}

// NewKeyGenerator returns a key generator with given options.
// By default, it uses pkcs1 to encode/decode private key and pkix to encode/decode public key.
// You can specify your encoder or decoder.
func NewKeyGenerator(opts ...GeneratorOption) *KeyGenerator {
	generator := &KeyGenerator{
		privateKeyEncoder: X509.PKCS1PrivateKeyEncoder,
		publicKeyEncoder:  X509.PKIXPublicKeyEncoder,
		privateKeyDecoder: X509.PKCS1PrivateKeyDecoder,
	}

	for _, opt := range opts {
		opt.ApplyTo(generator)
	}

	return generator
}

// GenerateKey generates a key set of bits.
func (kg *KeyGenerator) GenerateKey(bits int) (*Key, error) {
	privateKey, privateKeyBytes, err := kg.GeneratePrivateKey(bits)
	if err != nil {
		return nil, err
	}

	publicKey, publicKeyBytes, err := kg.GeneratePublicKey(privateKey)
	if err != nil {
		return nil, err
	}

	return &Key{
		Private:      privateKey,
		Public:       publicKey,
		PublicBytes:  publicKeyBytes,
		PrivateBytes: privateKeyBytes,
	}, nil
}

// GeneratePrivateKey generates a private key of bits.
// It returns an original key struct (*rsa.PrivateKey) and a completing key bytes (cryptox.Bytes).
func (kg *KeyGenerator) GeneratePrivateKey(bits int) (*rsa.PrivateKey, cryptox.Bytes, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}

	privateKeyBytes, err := kg.privateKeyEncoder.Encode(privateKey)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, privateKeyBytes, nil
}

// GeneratePublicKey generates a public key from private key.
// It returns an original key struct (*rsa.PublicKey) and a completing key bytes (cryptox.Bytes).
func (kg *KeyGenerator) GeneratePublicKey(privateKey *rsa.PrivateKey) (*rsa.PublicKey, cryptox.Bytes, error) {
	publicKey := &privateKey.PublicKey

	publicKeyBytes, err := kg.publicKeyEncoder.Encode(publicKey)
	if err != nil {
		return nil, nil, err
	}

	return publicKey, publicKeyBytes, nil
}

// GeneratePublicKeyFromFile generates a public key from private key file.
// It returns an original key struct (*rsa.PublicKey) and a completing key bytes (cryptox.Bytes).
func (kg *KeyGenerator) GeneratePublicKeyFromFile(privateKeyFile string) (*rsa.PublicKey, cryptox.Bytes, error) {
	privateKeyPem, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return nil, nil, err
	}

	privateKey, err := kg.privateKeyDecoder.Decode(privateKeyPem)
	if err != nil {
		return nil, nil, err
	}

	return kg.GeneratePublicKey(privateKey)
}
