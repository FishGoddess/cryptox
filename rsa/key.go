// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"io"
	"io/ioutil"

	"github.com/FishGoddess/cryptox"
)

// GenerateKeys generates a key set of bits.
func GenerateKeys(bits int, opts ...KeyOption) (PrivateKey, PublicKey, error) {
	privateKey, err := GeneratePrivateKey(bits, opts...)
	if err != nil {
		return PrivateKey{}, PublicKey{}, err
	}

	publicKey, err := GeneratePublicKey(privateKey, opts...)
	if err != nil {
		return PrivateKey{}, PublicKey{}, err
	}

	return privateKey, publicKey, nil
}

// GeneratePrivateKey generates a private key of bits.
// It returns an original key struct (*rsa.PrivateKey) and a completing key bytes (cryptox.Bytes).
func GeneratePrivateKey(bits int, opts ...KeyOption) (PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return PrivateKey{}, err
	}

	cfg := fromKeyOptions(opts...)

	privateKeyBytes, err := cfg.privateKeyEncoder.Encode(privateKey)
	if err != nil {
		return PrivateKey{}, err
	}

	return newPrivateKey(privateKey, privateKeyBytes), nil
}

// GeneratePublicKey generates a public key from private key.
// It returns an original key struct (*rsa.PublicKey) and a completing key bytes (cryptox.Bytes).
func GeneratePublicKey(privateKey PrivateKey, opts ...KeyOption) (PublicKey, error) {
	publicKey := &(privateKey.Key().PublicKey)
	cfg := fromKeyOptions(opts...)

	publicKeyBytes, err := cfg.publicKeyEncoder.Encode(publicKey)
	if err != nil {
		return PublicKey{}, err
	}

	return newPublicKey(publicKey, publicKeyBytes), nil
}

// ParsePrivateKey parses private key from pem.
func ParsePrivateKey(keyPem cryptox.Bytes, opts ...KeyOption) (*rsa.PrivateKey, error) {
	cfg := fromKeyOptions(opts...)
	return cfg.privateKeyDecoder.Decode(keyPem)
}

// ParsePublicKey parses public key from pem.
func ParsePublicKey(keyPem cryptox.Bytes, opts ...KeyOption) (*rsa.PublicKey, error) {
	cfg := fromKeyOptions(opts...)
	return cfg.publicKeyDecoder.Decode(keyPem)
}

// ReadPrivateKey reads private key from a reader.
func ReadPrivateKey(keyReader io.Reader, opts ...KeyOption) (*rsa.PrivateKey, error) {
	keyPem, err := ioutil.ReadAll(keyReader)
	if err != nil {
		return nil, err
	}

	return ParsePrivateKey(keyPem, opts...)
}

// ReadPublicKey reads public key from a reader.
func ReadPublicKey(keyReader io.Reader, opts ...KeyOption) (*rsa.PublicKey, error) {
	keyPem, err := ioutil.ReadAll(keyReader)
	if err != nil {
		return nil, err
	}

	return ParsePublicKey(keyPem, opts...)
}

// LoadPrivateKey loads private key from a file.
func LoadPrivateKey(keyFile string, opts ...KeyOption) (*rsa.PrivateKey, error) {
	keyPem, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	return ParsePrivateKey(keyPem, opts...)
}

// LoadPublicKey loads public key from a file.
func LoadPublicKey(keyFile string, opts ...KeyOption) (*rsa.PublicKey, error) {
	keyPem, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	return ParsePublicKey(keyPem, opts...)
}

// MustLoadPrivateKey loads private key from a file or panic on failed.
func MustLoadPrivateKey(keyFile string, opts ...KeyOption) *rsa.PrivateKey {
	key, err := LoadPrivateKey(keyFile, opts...)
	if err != nil {
		panic(err)
	}

	return key
}

// MustLoadPublicKey loads public key from a file or panic on failed.
func MustLoadPublicKey(keyFile string, opts ...KeyOption) *rsa.PublicKey {
	key, err := LoadPublicKey(keyFile, opts...)
	if err != nil {
		panic(err)
	}

	return key
}
