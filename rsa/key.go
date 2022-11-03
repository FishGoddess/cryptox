// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"io"
	"io/ioutil"
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

// WritePrivateTo writes private key to writer.
func (k Key) WritePrivateTo(privateWriter io.Writer) (n int, err error) {
	return privateWriter.Write(k.Private)
}

// WritePublicTo writes public key to writer.
func (k Key) WritePublicTo(publicWriter io.Writer) (n int, err error) {
	return publicWriter.Write(k.Public)
}

// WriteTo writes private key and public key to writer.
func (k Key) WriteTo(privateWriter io.Writer, publicWriter io.Writer) (n int, err error) {
	n, err = k.WritePrivateTo(privateWriter)
	if err != nil {
		return n, err
	}

	nn, err := k.WritePublicTo(publicWriter)
	if err != nil {
		return n + nn, err
	}

	return n + nn, nil
}

// WritePrivateToFile writes private key to file.
func (k Key) WritePrivateToFile(privatePath string) (n int, err error) {
	privateFile, err := k.newFile(privatePath)
	if err != nil {
		return 0, err
	}

	defer privateFile.Close()
	return k.WritePrivateTo(privateFile)
}

// WritePublicToFile writes public key to file.
func (k Key) WritePublicToFile(publicPath string) (n int, err error) {
	publicFile, err := k.newFile(publicPath)
	if err != nil {
		return 0, err
	}

	defer publicFile.Close()

	return k.WritePublicTo(publicFile)
}

// WriteToFile writes private key and public key to file.
func (k Key) WriteToFile(privatePath string, publicPath string) (n int, err error) {
	n, err = k.WritePrivateToFile(privatePath)
	if err != nil {
		return n, err
	}

	nn, err := k.WritePublicToFile(publicPath)
	if err != nil {
		return n + nn, err
	}

	return n + nn, nil
}

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
		privateKeyEncoder: PKCS1PrivateKeyEncoder,
		publicKeyEncoder:  PKIXPublicKeyEncoder,
		privateKeyDecoder: PKCS1PrivateKeyDecoder,
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

// KeyLoader is a loader for loading rsa key including private and public.
type KeyLoader struct {
	privateKeyDecoder PrivateKeyDecoder
	publicKeyDecoder  PublicKeyDecoder
}

// NewKeyLoader returns a key loader with given options.
// By default, it uses pkcs1 to decode private key and pkix to decode public key.
// You can specify your decoder.
func NewKeyLoader(opts ...LoaderOption) *KeyLoader {
	loader := &KeyLoader{
		privateKeyDecoder: PKCS1PrivateKeyDecoder,
		publicKeyDecoder:  PKIXPublicKeyDecoder,
	}

	for _, opt := range opts {
		opt.ApplyTo(loader)
	}

	return loader
}

// ParsePrivateKey parses private key from pem.
func (kl *KeyLoader) ParsePrivateKey(keyPem cryptox.Bytes) (*rsa.PrivateKey, error) {
	return kl.privateKeyDecoder.Decode(keyPem)
}

// ParsePublicKey parses public key from pem.
func (kl *KeyLoader) ParsePublicKey(keyPem cryptox.Bytes) (*rsa.PublicKey, error) {
	return kl.publicKeyDecoder.Decode(keyPem)
}

// LoadPrivateKey loads private key from a file.
func (kl *KeyLoader) LoadPrivateKey(keyFile string) (*rsa.PrivateKey, error) {
	keyPem, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	return kl.ParsePrivateKey(keyPem)
}

// LoadPublicKey loads public key from a file.
func (kl *KeyLoader) LoadPublicKey(keyFile string) (*rsa.PublicKey, error) {
	keyPem, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	return kl.ParsePublicKey(keyPem)
}

// LoadPrivateKeyFrom loads private key from a reader.
func (kl *KeyLoader) LoadPrivateKeyFrom(keyReader io.Reader) (*rsa.PrivateKey, error) {
	keyPem, err := ioutil.ReadAll(keyReader)
	if err != nil {
		return nil, err
	}

	return kl.ParsePrivateKey(keyPem)
}

// LoadPublicKeyFrom loads public key from a reader.
func (kl *KeyLoader) LoadPublicKeyFrom(keyReader io.Reader) (*rsa.PublicKey, error) {
	keyPem, err := ioutil.ReadAll(keyReader)
	if err != nil {
		return nil, err
	}

	return kl.ParsePublicKey(keyPem)
}

// MustLoadPrivateKey loads private key from a file or panic on failed.
func (kl *KeyLoader) MustLoadPrivateKey(keyFile string) *rsa.PrivateKey {
	key, err := kl.LoadPrivateKey(keyFile)
	if err != nil {
		panic(err)
	}

	return key
}

// MustLoadPublicKey loads public key from a file or panic on failed.
func (kl *KeyLoader) MustLoadPublicKey(keyFile string) *rsa.PublicKey {
	key, err := kl.LoadPublicKey(keyFile)
	if err != nil {
		panic(err)
	}

	return key
}
