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
func GeneratePublicKey(privateKey PrivateKey, opts ...KeyOption) (PublicKey, error) {
	publicKey := &(privateKey.Key().PublicKey)
	cfg := fromKeyOptions(opts...)

	publicKeyBytes, err := cfg.publicKeyEncoder.Encode(publicKey)
	if err != nil {
		return PublicKey{}, err
	}

	return newPublicKey(publicKey, publicKeyBytes), nil
}

// ParsePrivateKey parses private key from pem bytes.
func ParsePrivateKey(keyBytes cryptox.Bytes, opts ...KeyOption) (PrivateKey, error) {
	cfg := fromKeyOptions(opts...)

	privateKey, err := cfg.privateKeyDecoder.Decode(keyBytes)
	if err != nil {
		return PrivateKey{}, nil
	}

	return newPrivateKey(privateKey, keyBytes), nil
}

// ParsePublicKey parses public key from pem bytes.
func ParsePublicKey(keyBytes cryptox.Bytes, opts ...KeyOption) (PublicKey, error) {
	cfg := fromKeyOptions(opts...)

	publicKey, err := cfg.publicKeyDecoder.Decode(keyBytes)
	if err != nil {
		return PublicKey{}, nil
	}

	return newPublicKey(publicKey, keyBytes), nil
}

// ReadPrivateKey reads private key from a reader.
func ReadPrivateKey(keyReader io.Reader, opts ...KeyOption) (PrivateKey, error) {
	keyBytes, err := ioutil.ReadAll(keyReader)
	if err != nil {
		return PrivateKey{}, err
	}

	return ParsePrivateKey(keyBytes, opts...)
}

// ReadPublicKey reads public key from a reader.
func ReadPublicKey(keyReader io.Reader, opts ...KeyOption) (PublicKey, error) {
	keyBytes, err := ioutil.ReadAll(keyReader)
	if err != nil {
		return PublicKey{}, err
	}

	return ParsePublicKey(keyBytes, opts...)
}

// LoadPrivateKey loads private key from a file.
func LoadPrivateKey(keyFile string, opts ...KeyOption) (PrivateKey, error) {
	keyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return PrivateKey{}, err
	}

	return ParsePrivateKey(keyBytes, opts...)
}

// LoadPublicKey loads public key from a file.
func LoadPublicKey(keyFile string, opts ...KeyOption) (PublicKey, error) {
	keyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return PublicKey{}, err
	}

	return ParsePublicKey(keyBytes, opts...)
}

// MustLoadPrivateKey loads private key from a file or panic on failed.
func MustLoadPrivateKey(keyFile string, opts ...KeyOption) PrivateKey {
	key, err := LoadPrivateKey(keyFile, opts...)
	if err != nil {
		panic(err)
	}

	return key
}

// MustLoadPublicKey loads public key from a file or panic on failed.
func MustLoadPublicKey(keyFile string, opts ...KeyOption) PublicKey {
	key, err := LoadPublicKey(keyFile, opts...)
	if err != nil {
		panic(err)
	}

	return key
}
