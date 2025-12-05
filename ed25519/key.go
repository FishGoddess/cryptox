// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package ed25519

import (
	"crypto/ed25519"
	"io"
	"os"
)

// GenerateKeys generates a private key and a public key.
func GenerateKeys(opts ...KeyOption) (PrivateKey, PublicKey, error) {
	conf := newKeyConfig().Apply(opts...)

	var key ed25519.PrivateKey
	var pkey ed25519.PublicKey
	var err error

	if len(conf.seed) > 0 {
		key = ed25519.NewKeyFromSeed(conf.seed)
		pkey = key.Public().(ed25519.PublicKey)
	} else {
		pkey, key, err = ed25519.GenerateKey(conf.random)
	}

	if err != nil {
		return PrivateKey{}, PublicKey{}, err
	}

	privateKey := PrivateKey{key: key}
	publicKey := PublicKey{key: pkey}
	return privateKey, publicKey, nil
}

// WritePrivateKey writes the private key to the writer.
func WritePrivateKey(writer io.Writer, privateKey PrivateKey, opts ...KeyOption) error {
	conf := newKeyConfig().Apply(opts...)

	data, err := conf.encodePrivateKey(privateKey.key)
	if err != nil {
		return err
	}

	_, err = writer.Write(data)
	return err
}

// WritePublicKey writes the public key to the writer.
func WritePublicKey(writer io.Writer, publicKey PublicKey, opts ...KeyOption) error {
	conf := newKeyConfig().Apply(opts...)

	data, err := conf.encodePublicKey(publicKey.key)
	if err != nil {
		return err
	}

	_, err = writer.Write(data)
	return err
}

// ReadPrivateKey reads the private key from the reader.
func ReadPrivateKey(reader io.Reader, opts ...KeyOption) (PrivateKey, error) {
	conf := newKeyConfig().Apply(opts...)

	data, err := io.ReadAll(reader)
	if err != nil {
		return PrivateKey{}, err
	}

	key, err := conf.decodePrivateKey(data)
	if err != nil {
		return PrivateKey{}, err
	}

	privateKey := PrivateKey{key: key}
	return privateKey, nil
}

// ReadPublicKey reads the public key from the reader.
func ReadPublicKey(reader io.Reader, opts ...KeyOption) (PublicKey, error) {
	conf := newKeyConfig().Apply(opts...)

	data, err := io.ReadAll(reader)
	if err != nil {
		return PublicKey{}, err
	}

	key, err := conf.decodePublicKey(data)
	if err != nil {
		return PublicKey{}, err
	}

	publicKey := PublicKey{key: key}
	return publicKey, nil
}

func newFile(file string) (*os.File, error) {
	flag := os.O_CREATE | os.O_WRONLY | os.O_EXCL
	perm := os.FileMode(0644)
	return os.OpenFile(file, flag, perm)
}

// StorePrivateKey stores the private key to the file.
func StorePrivateKey(file string, privateKey PrivateKey, opts ...KeyOption) error {
	f, err := newFile(file)
	if err != nil {
		return err
	}

	defer f.Close()
	return WritePrivateKey(f, privateKey, opts...)
}

// StorePublicKey stores the public key to the file.
func StorePublicKey(file string, publicKey PublicKey, opts ...KeyOption) error {
	f, err := newFile(file)
	if err != nil {
		return err
	}

	defer f.Close()
	return WritePublicKey(f, publicKey, opts...)
}

// LoadPrivateKey loads the private key from the file.
func LoadPrivateKey(file string, opts ...KeyOption) (PrivateKey, error) {
	f, err := os.Open(file)
	if err != nil {
		return PrivateKey{}, err
	}

	defer f.Close()
	return ReadPrivateKey(f, opts...)
}

// LoadPublicKey loads the public key from the file.
func LoadPublicKey(file string, opts ...KeyOption) (PublicKey, error) {
	f, err := os.Open(file)
	if err != nil {
		return PublicKey{}, err
	}

	defer f.Close()
	return ReadPublicKey(f, opts...)
}
