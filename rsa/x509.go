// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/FishGoddess/cryptox"
)

const (
	blockTypePrivate = "RSA Private Key"
	blockTypePublic  = "RSA Public Key"
)

var (
	_ PrivateKeyEncoder = PKCS1PrivateKeyEncoder
	_ PrivateKeyDecoder = PKCS1PrivateKeyDecoder
	_ PublicKeyEncoder  = PKIXPublicKeyEncoder
	_ PublicKeyDecoder  = PKIXPublicKeyDecoder
)

type PrivateKeyEncoder func(key *rsa.PrivateKey) (cryptox.Bytes, error)

func (pke PrivateKeyEncoder) Encode(key *rsa.PrivateKey) (cryptox.Bytes, error) {
	return pke(key)
}

type PrivateKeyDecoder func(keyPem cryptox.Bytes) (*rsa.PrivateKey, error)

func (pke PrivateKeyDecoder) Decode(keyPem cryptox.Bytes) (*rsa.PrivateKey, error) {
	return pke(keyPem)
}

type PublicKeyEncoder func(key *rsa.PublicKey) (cryptox.Bytes, error)

func (pke PublicKeyEncoder) Encode(key *rsa.PublicKey) (cryptox.Bytes, error) {
	return pke(key)
}

type PublicKeyDecoder func(keyPem cryptox.Bytes) (*rsa.PublicKey, error)

func (pke PublicKeyDecoder) Decode(keyPem cryptox.Bytes) (*rsa.PublicKey, error) {
	return pke(keyPem)
}

func encode(blockType string, blockBytes cryptox.Bytes) (cryptox.Bytes, error) {
	block := &pem.Block{
		Type:  blockType,
		Bytes: blockBytes,
	}

	var keyPem bytes.Buffer
	if err := pem.Encode(&keyPem, block); err != nil {
		return nil, err
	}

	return keyPem.Bytes(), nil
}

func decode(blockType string, keyPem cryptox.Bytes) (*pem.Block, error) {
	block, _ := pem.Decode(keyPem)
	if block == nil {
		return nil, fmt.Errorf("cryptox.rsa: decode %s from pem failed", strings.ToLower(blockType))
	}

	return block, nil
}

// PKCS1PrivateKeyEncoder encodes private key to bytes using pkcs1.
func PKCS1PrivateKeyEncoder(key *rsa.PrivateKey) (cryptox.Bytes, error) {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(key)
	return encode(blockTypePrivate, privateKeyBytes)
}

// PKCS1PrivateKeyDecoder decodes private key from data using pkcs1.
func PKCS1PrivateKeyDecoder(privateKeyPem cryptox.Bytes) (*rsa.PrivateKey, error) {
	block, err := decode(blockTypePrivate, privateKeyPem)
	if err != nil {
		return nil, err
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// PKIXPublicKeyEncoder encodes public key to bytes using pkix.
func PKIXPublicKeyEncoder(key *rsa.PublicKey) (cryptox.Bytes, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}

	return encode(blockTypePublic, publicKeyBytes)
}

// PKIXPublicKeyDecoder encodes public key to bytes using pkix.
func PKIXPublicKeyDecoder(publicKeyPem cryptox.Bytes) (*rsa.PublicKey, error) {
	block, err := decode(blockTypePublic, publicKeyPem)
	if err != nil {
		return nil, err
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	publicKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("cryptox.rsa: parsed key %T isn't a *rsa.PublicKey", key)
	}

	return publicKey, nil
}
