// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package x509

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// go test -v -cover -run=^TestPrivateKeyPKCS1$
func TestPrivateKeyPKCS1(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	data, err := EncodePrivateKeyPKCS1(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	decodeKey, err := DecodePrivateKeyPKCS1(data)
	if err != nil {
		t.Fatal(err)
	}

	if !decodeKey.Equal(privateKey) {
		t.Fatalf("decodeKey %+v != privateKey %+v", decodeKey, privateKey)
	}
}

// go test -v -cover -run=^TestPrivateKeyPKCS8$
func TestPrivateKeyPKCS8(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	data, err := EncodePrivateKeyPKCS8(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	decodeKey, err := DecodePrivateKeyPKCS8[*rsa.PrivateKey](data)
	if err != nil {
		t.Fatal(err)
	}

	if !decodeKey.Equal(privateKey) {
		t.Fatalf("decodeKey %+v != privateKey %+v", decodeKey, privateKey)
	}
}

// go test -v -cover -run=^TestPublicKeyPKCS1$
func TestPublicKeyPKCS1(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	publicKey := &privateKey.PublicKey

	data, err := EncodePublicKeyPKCS1(publicKey)
	if err != nil {
		t.Fatal(err)
	}

	decodeKey, err := DecodePublicKeyPKCS1(data)
	if err != nil {
		t.Fatal(err)
	}

	if !decodeKey.Equal(publicKey) {
		t.Fatalf("decodeKey %+v != publicKey %+v", decodeKey, publicKey)
	}
}

// go test -v -cover -run=^TestPublicKeyPKIX$
func TestPublicKeyPKIX(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	publicKey := &privateKey.PublicKey

	data, err := EncodePublicKeyPKIX(publicKey)
	if err != nil {
		t.Fatal(err)
	}

	decodeKey, err := DecodePublicKeyPKIX[*rsa.PublicKey](data)
	if err != nil {
		t.Fatal(err)
	}

	if !decodeKey.Equal(publicKey) {
		t.Fatalf("decodeKey %+v != publicKey %+v", decodeKey, publicKey)
	}
}
