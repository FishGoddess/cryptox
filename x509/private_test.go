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

	bs, err := EncodePrivateKeyPKCS1(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	decodeKey, err := DecodePrivateKeyPKCS1(bs)
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

	bs, err := EncodePrivateKeyPKCS8(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	decodeKey, err := DecodePrivateKeyPKCS8[*rsa.PrivateKey](bs)
	if err != nil {
		t.Fatal(err)
	}

	if !decodeKey.Equal(privateKey) {
		t.Fatalf("decodeKey %+v != privateKey %+v", decodeKey, privateKey)
	}
}
