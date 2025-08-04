// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package ecc

import (
	"crypto/ed25519"
	"io"
	"os"

	"github.com/FishGoddess/cryptox"
)

// GenerateKeys generates a key set.
func GenerateKeys() (PrivateKey, PublicKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return PrivateKey{}, PublicKey{}, err
	}

	newPrivateKey := newPrivateKey(privateKey)
	newPublicKey := newPublicKey(publicKey)
	return newPrivateKey, newPublicKey, nil
}

// GeneratePrivateKey generates a private key.
func GeneratePrivateKey() (PrivateKey, error) {
	privateKey, _, err := GenerateKeys()
	return privateKey, err
}

// GeneratePublicKey generates a public key from private key.
func GeneratePublicKey(privateKey PrivateKey) (PublicKey, error) {
	publicKey := privateKey.Key().Public().(ed25519.PublicKey)
	newPublicKey := newPublicKey(publicKey)
	return newPublicKey, nil
}

// ParsePrivateKey parses a private key from bytes.
func ParsePrivateKey(keyBytes cryptox.Bytes) (PrivateKey, error) {
	privateKey := ed25519.PrivateKey(keyBytes)
	newPrivateKey := newPrivateKey(privateKey)
	return newPrivateKey, nil
}

// ParsePublicKey parses a public key from bytes.
func ParsePublicKey(keyBytes cryptox.Bytes) (PublicKey, error) {
	publicKey := ed25519.PublicKey(keyBytes)
	newPublicKey := newPublicKey(publicKey)
	return newPublicKey, nil
}

// ReadPrivateKey reads a private key from a reader.
func ReadPrivateKey(keyReader io.Reader) (PrivateKey, error) {
	keyBytes, err := io.ReadAll(keyReader)
	if err != nil {
		return PrivateKey{}, err
	}

	return ParsePrivateKey(keyBytes)
}

// ReadPublicKey reads a public key from a reader.
func ReadPublicKey(keyReader io.Reader) (PublicKey, error) {
	keyBytes, err := io.ReadAll(keyReader)
	if err != nil {
		return PublicKey{}, err
	}

	return ParsePublicKey(keyBytes)
}

// LoadPrivateKey loads a private key from a file.
func LoadPrivateKey(keyFile string) (PrivateKey, error) {
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return PrivateKey{}, err
	}

	return ParsePrivateKey(keyBytes)
}

// LoadPublicKey loads a public key from a file.
func LoadPublicKey(keyFile string) (PublicKey, error) {
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return PublicKey{}, err
	}

	return ParsePublicKey(keyBytes)
}

// MustLoadPrivateKey loads private key from a file or panic if failed.
func MustLoadPrivateKey(keyFile string) PrivateKey {
	key, err := LoadPrivateKey(keyFile)
	if err != nil {
		panic(err)
	}

	return key
}

// MustLoadPublicKey loads public key from a file or panic if failed.
func MustLoadPublicKey(keyFile string) PublicKey {
	key, err := LoadPublicKey(keyFile)
	if err != nil {
		panic(err)
	}

	return key
}
