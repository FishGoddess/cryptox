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
	blockTypePublic    = "PUBLIC KEY"
	blockTypePublicRSA = "RSA PUBLIC KEY"
)

// EncodePublicKeyPKCS1 uses pkcs1 to encode public key.
func EncodePublicKeyPKCS1(key *rsa.PublicKey) ([]byte, error) {
	blockBytes := x509.MarshalPKCS1PublicKey(key)
	return encode(blockTypePublicRSA, blockBytes)
}

// EncodePublicKeyPKIX uses pkix to encode public key.
func EncodePublicKeyPKIX[Key any](key Key) ([]byte, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}

	return encode(blockTypePublic, publicKeyBytes)
}

// DecodePublicKeyPKCS1 uses pkcs1 to decode public key.
func DecodePublicKeyPKCS1(bs []byte) (*rsa.PublicKey, error) {
	_, blockBytes, err := decode(bs)
	if err != nil {
		return nil, err
	}

	return x509.ParsePKCS1PublicKey(blockBytes)
}

// DecodePublicKeyPKIX uses pkix to decode public key.
func DecodePublicKeyPKIX[Key any](bs []byte) (Key, error) {
	_, blockBytes, err := decode(bs)
	if err != nil {
		var empty Key
		return empty, err
	}

	pk, err := x509.ParsePKIXPublicKey(blockBytes)
	if err != nil {
		var empty Key
		return empty, err
	}

	publicKey, ok := pk.(Key)
	if !ok {
		var empty Key
		return empty, fmt.Errorf("cryptox/x509: got type %T but expect type %T", pk, empty)
	}

	return publicKey, nil
}
