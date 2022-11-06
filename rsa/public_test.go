// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// go test -v -cover -run=^TestPublicKey$
func TestPublicKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
	}

	publicKey := &privateKey.PublicKey

	publicKeyBytes, err := X509.PKIXPublicKeyEncoder(publicKey)
	if err != nil {
		t.Error(err)
	}

	key := newPublicKey(publicKey, publicKeyBytes)
	if key.key != publicKey {
		t.Errorf("key.key %+v != publicKey %+v", key.key, publicKey)
	}

	if key.keyBytes.String() != publicKeyBytes.String() {
		t.Errorf("key.keyBytes %+v != publicKeyBytes %+v", key.keyBytes, publicKeyBytes)
	}

	if key.Key() != publicKey {
		t.Errorf("key.Key() %+v != publicKey %+v", key.Key(), publicKey)
	}

	if key.Bytes().String() != publicKeyBytes.String() {
		t.Errorf("key.Bytes() %+v != publicKeyBytes %+v", key.Bytes(), publicKeyBytes)
	}

	expectPublicKey := PublicKey{
		key:      publicKey,
		keyBytes: publicKeyBytes,
	}

	if !key.EqualsTo(expectPublicKey) {
		t.Errorf("key %+v != expectPublicKey %+v", key, expectPublicKey)
	}

	if key.String() != publicKeyBytes.String() {
		t.Errorf("key.String() %+v != publicKeyBytes %+v", key.String(), publicKeyBytes)
	}
}
