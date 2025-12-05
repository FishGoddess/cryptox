// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package x509

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

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
