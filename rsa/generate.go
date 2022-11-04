// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"io/ioutil"
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

// GenerateKeys generates a key set of bits.
func (kg *KeyGenerator) GenerateKeys(bits int) (PrivateKey, PublicKey, error) {
	privateKey, err := kg.GeneratePrivateKey(bits)
	if err != nil {
		return PrivateKey{}, PublicKey{}, err
	}

	publicKey, err := kg.GeneratePublicKey(privateKey)
	if err != nil {
		return PrivateKey{}, PublicKey{}, err
	}

	return privateKey, publicKey, nil
}

// GeneratePrivateKey generates a private key of bits.
// It returns an original key struct (*rsa.PrivateKey) and a completing key bytes (cryptox.Bytes).
func (kg *KeyGenerator) GeneratePrivateKey(bits int) (PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return PrivateKey{}, err
	}

	privateKeyBytes, err := kg.privateKeyEncoder.Encode(privateKey)
	if err != nil {
		return PrivateKey{}, err
	}

	return newPrivateKey(privateKey, privateKeyBytes), nil
}

// GeneratePublicKey generates a public key from private key.
// It returns an original key struct (*rsa.PublicKey) and a completing key bytes (cryptox.Bytes).
func (kg *KeyGenerator) GeneratePublicKey(privateKey PrivateKey) (PublicKey, error) {
	publicKey := &privateKey.Key().PublicKey

	publicKeyBytes, err := kg.publicKeyEncoder.Encode(publicKey)
	if err != nil {
		return PublicKey{}, err
	}

	return newPublicKey(publicKey, publicKeyBytes), nil
}

// GeneratePublicKeyFromFile generates a public key from private key file.
// It returns an original key struct (*rsa.PublicKey) and a completing key bytes (cryptox.Bytes).
func (kg *KeyGenerator) GeneratePublicKeyFromFile(privateKeyFile string) (PublicKey, error) {
	privateKeyBytes, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return PublicKey{}, err
	}

	privateKey, err := kg.privateKeyDecoder.Decode(privateKeyBytes)
	if err != nil {
		return PublicKey{}, err
	}

	return kg.GeneratePublicKey(newPrivateKey(privateKey, privateKeyBytes))
}
