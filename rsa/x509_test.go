// Copyright 2023 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// go test -v -cover -run=^TestPKCS1PrivateKey$
func TestPKCS1PrivateKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
	}

	privateKeyBytes, err := X509.PKCS1PrivateKeyEncoder(privateKey)
	if err != nil {
		t.Error(err)
	}

	decodedPrivateKey, err := X509.PKCS1PrivateKeyDecoder(privateKeyBytes)
	if err != nil {
		t.Error(err)
	}

	if !decodedPrivateKey.Equal(privateKey) {
		t.Errorf("decodedPrivateKey %+v != privateKey %+v", decodedPrivateKey, privateKey)
	}
}

// go test -v -cover -run=^TestPKCS8PrivateKey$
func TestPKCS8PrivateKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
	}

	privateKeyBytes, err := X509.PKCS8PrivateKeyEncoder(privateKey)
	if err != nil {
		t.Error(err)
	}

	decodedPrivateKey, err := X509.PKCS8PrivateKeyDecoder(privateKeyBytes)
	if err != nil {
		t.Error(err)
	}

	if !decodedPrivateKey.Equal(privateKey) {
		t.Errorf("decodedPrivateKey %+v != privateKey %+v", decodedPrivateKey, privateKey)
	}
}

// go test -v -cover -run=^TestPKIXPublicKey$
func TestPKIXPublicKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
	}

	publicKey := &privateKey.PublicKey

	publicKeyBytes, err := X509.PKIXPublicKeyEncoder(publicKey)
	if err != nil {
		t.Error(err)
	}

	decodedPublicKey, err := X509.PKIXPublicKeyDecoder(publicKeyBytes)
	if err != nil {
		t.Error(err)
	}

	if !decodedPublicKey.Equal(publicKey) {
		t.Errorf("decodedPublicKey %+v != publicKey %+v", decodedPublicKey, publicKey)
	}
}

// go test -v -cover -run=^TestPKCS1PublicKey$
func TestPKCS1PublicKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
	}

	publicKey := &privateKey.PublicKey

	publicKeyBytes, err := X509.PKCS1PublicKeyEncoder(publicKey)
	if err != nil {
		t.Error(err)
	}

	decodedPublicKey, err := X509.PKCS1PublicKeyDecoder(publicKeyBytes)
	if err != nil {
		t.Error(err)
	}

	if !decodedPublicKey.Equal(publicKey) {
		t.Errorf("decodedPublicKey %+v != publicKey %+v", decodedPublicKey, publicKey)
	}
}
