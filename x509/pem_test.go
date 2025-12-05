// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package x509

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"slices"
	"testing"
)

// go test -v -cover -run=^TestPem$
func TestPem(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	blockBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	data, err := encode(blockTypePrivate, blockBytes)
	if err != nil {
		t.Fatal(err)
	}

	decodeType, decodeBytes, err := decode(data)
	if err != nil {
		t.Fatal(err)
	}

	if decodeType != blockTypePrivate {
		t.Fatalf("decodeType %s != blockTypePrivate %s", decodeType, blockTypePrivate)
	}

	if !slices.Equal(decodeBytes, blockBytes) {
		t.Fatalf("decodeBytes %s != blockBytes %s", decodeBytes, blockBytes)
	}

	pk, err := x509.ParsePKCS8PrivateKey(decodeBytes)
	if err != nil {
		t.Fatal(err)
	}

	decodeKey, ok := pk.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("got type %T is wrong", pk)
	}

	if !decodeKey.Equal(privateKey) {
		t.Fatalf("decodeKey %+v != privateKey %+v", decodeKey, privateKey)
	}
}
