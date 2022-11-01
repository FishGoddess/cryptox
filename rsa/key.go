// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"io"
	"os"

	"github.com/FishGoddess/cryptox"
)

var (
	// KeyFileFlag is the flag of key file.
	KeyFileFlag = os.O_CREATE | os.O_APPEND | os.O_WRONLY

	// KeyFileMode is the mode of key file.
	KeyFileMode os.FileMode = 0644
)

// Key stores public key and private key of rsa.
type Key struct {
	Private cryptox.Bytes
	Public  cryptox.Bytes
}

// newFile creates a new file of path.
func (k Key) newFile(path string) (*os.File, error) {
	return os.OpenFile(path, KeyFileFlag, KeyFileMode)
}

// WriteTo writes private key and public key to writer.
func (k Key) WriteTo(privateWriter io.Writer, publicWriter io.Writer) (n int, err error) {
	n, err = privateWriter.Write(k.Private)
	if err != nil {
		return n, err
	}

	nn, err := publicWriter.Write(k.Public)
	if err != nil {
		return n + nn, err
	}

	return n + nn, nil
}

// WriteToFile writes private key and public key to file.
func (k Key) WriteToFile(privatePath string, publicPath string) (n int, err error) {
	privateFile, err := k.newFile(privatePath)
	if err != nil {
		return 0, err
	}

	defer privateFile.Close()

	publicFile, err := k.newFile(publicPath)
	if err != nil {
		return 0, err
	}

	defer publicFile.Close()

	return k.WriteTo(privateFile, publicFile)
}

// Option is a function for setting key generator.
type Option func(generator *KeyGenerator)

// ApplyTo applies option to generator.
func (o Option) ApplyTo(generator *KeyGenerator) {
	o(generator)
}

// WithPrivateKeyEncoder sets private key encoder to generator.
func WithPrivateKeyEncoder(encoder PrivateKeyEncoder) Option {
	return func(generator *KeyGenerator) {
		generator.privateKeyEncoder = encoder
	}
}

// WithPrivateKeyDecoder sets private key decoder to generator.
func WithPrivateKeyDecoder(decoder PrivateKeyDecoder) Option {
	return func(generator *KeyGenerator) {
		generator.privateKeyDecoder = decoder
	}
}

// WithPublicKeyEncoder sets public key encoder to generator.
func WithPublicKeyEncoder(encoder PublicKeyEncoder) Option {
	return func(generator *KeyGenerator) {
		generator.publicKeyEncoder = encoder
	}
}

// WithPublicKeyDecoder sets public key decoder to generator.
func WithPublicKeyDecoder(decoder PublicKeyDecoder) Option {
	return func(generator *KeyGenerator) {
		generator.publicKeyDecoder = decoder
	}
}

// KeyGenerator is a generator for generating rsa key including private and public.
type KeyGenerator struct {
	privateKeyEncoder PrivateKeyEncoder
	privateKeyDecoder PrivateKeyDecoder
	publicKeyEncoder  PublicKeyEncoder
	publicKeyDecoder  PublicKeyDecoder
}

// NewKeyGenerator returns a key generator with given options.
// By default, it uses pkcs1 to encode/decode private key and pkix to encode/decode public key.
// You can specify your encoder or decode.
func NewKeyGenerator(opts ...Option) *KeyGenerator {
	generator := &KeyGenerator{
		privateKeyEncoder: PKCS1PrivateKeyEncoder,
		privateKeyDecoder: PKCS1PrivateKeyDecoder,
		publicKeyEncoder:  PKIXPublicKeyEncoder,
		publicKeyDecoder:  PKIXPublicKeyDecoder,
	}

	for _, opt := range opts {
		opt.ApplyTo(generator)
	}

	return generator
}

// GenerateKey generates a key set of bits.
func (kg *KeyGenerator) GenerateKey(bits int) (Key, error) {
	privateKey, privateKeyBytes, err := kg.GeneratePrivateKey(bits)
	if err != nil {
		return Key{}, err
	}

	_, publicKeyBytes, err := kg.GeneratePublicKey(privateKey)
	if err != nil {
		return Key{}, err
	}

	return Key{Public: publicKeyBytes, Private: privateKeyBytes}, nil
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

// GeneratePublicKeyFromPem generates a public key from private key pem.
// It returns an original key struct (*rsa.PublicKey) and a completing key bytes (cryptox.Bytes).
func (kg *KeyGenerator) GeneratePublicKeyFromPem(privateKeyPem cryptox.Bytes) (*rsa.PublicKey, cryptox.Bytes, error) {
	privateKey, err := kg.ParsePrivateKey(privateKeyPem)
	if err != nil {
		return nil, nil, err
	}

	return kg.GeneratePublicKey(privateKey)
}

// ParsePrivateKey parses private key from pem.
func (kg *KeyGenerator) ParsePrivateKey(keyPem cryptox.Bytes) (*rsa.PrivateKey, error) {
	return kg.privateKeyDecoder.Decode(keyPem)
}

// ParsePublicKey parses public key from pem.
func (kg *KeyGenerator) ParsePublicKey(keyPem cryptox.Bytes) (*rsa.PublicKey, error) {
	return kg.publicKeyDecoder.Decode(keyPem)
}
