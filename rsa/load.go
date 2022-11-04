// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto/rsa"
	"io"
	"io/ioutil"

	"github.com/FishGoddess/cryptox"
)

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
		privateKeyDecoder: X509.PKCS1PrivateKeyDecoder,
		publicKeyDecoder:  X509.PKIXPublicKeyDecoder,
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

// ReadPrivateKey reads private key from a reader.
func (kl *KeyLoader) ReadPrivateKey(keyReader io.Reader) (*rsa.PrivateKey, error) {
	keyPem, err := ioutil.ReadAll(keyReader)
	if err != nil {
		return nil, err
	}

	return kl.ParsePrivateKey(keyPem)
}

// ReadPublicKey reads public key from a reader.
func (kl *KeyLoader) ReadPublicKey(keyReader io.Reader) (*rsa.PublicKey, error) {
	keyPem, err := ioutil.ReadAll(keyReader)
	if err != nil {
		return nil, err
	}

	return kl.ParsePublicKey(keyPem)
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
