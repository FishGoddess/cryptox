// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package x509

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

const (
	blockTypePrivate    = "PRIVATE KEY"
	blockTypePrivateRSA = "RSA PRIVATE KEY"
)

// EncodePrivateKeyPKCS1 uses pkcs1 to encode private key.
func EncodePrivateKeyPKCS1(key *rsa.PrivateKey) ([]byte, error) {
	blockBytes := x509.MarshalPKCS1PrivateKey(key)
	return encode(blockTypePrivateRSA, blockBytes)
}

// EncodePrivateKeyPKCS8 uses pkcs8 to encode private key.
func EncodePrivateKeyPKCS8[Key any](key Key) ([]byte, error) {
	blockBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	return encode(blockTypePrivate, blockBytes)
}

// DecodePrivateKeyPKCS1 uses pkcs1 to decode private key.
func DecodePrivateKeyPKCS1(data []byte) (*rsa.PrivateKey, error) {
	_, blockBytes, err := decode(data)
	if err != nil {
		return nil, err
	}

	return x509.ParsePKCS1PrivateKey(blockBytes)
}

// DecodePrivateKeyPKCS8 uses pkcs8 to decode private key.
func DecodePrivateKeyPKCS8[Key any](data []byte) (Key, error) {
	_, blockBytes, err := decode(data)
	if err != nil {
		var empty Key
		return empty, err
	}

	pk, err := x509.ParsePKCS8PrivateKey(blockBytes)
	if err != nil {
		var empty Key
		return empty, err
	}

	privateKey, ok := pk.(Key)
	if !ok {
		var empty Key
		return empty, fmt.Errorf("cryptox/x509: got type %T but expect type %T", pk, empty)
	}

	return privateKey, nil
}
