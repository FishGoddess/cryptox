// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// go test -v -cover -run=^TestPrivateKey$
func TestPrivateKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
	}

	privateKeyBytes, err := X509.PKCS1PrivateKeyEncoder(privateKey)
	if err != nil {
		t.Error(err)
	}

	key := newPrivateKey(privateKey, privateKeyBytes)
	if key.key != privateKey {
		t.Errorf("key.key %+v != privateKey %+v", key.key, privateKey)
	}

	if key.keyBytes.String() != privateKeyBytes.String() {
		t.Errorf("key.keyBytes %+v != privateKeyBytes %+v", key.keyBytes, privateKeyBytes)
	}

	if key.Key() != privateKey {
		t.Errorf("key.Key() %+v != privateKey %+v", key.Key(), privateKey)
	}

	if key.Bytes().String() != privateKeyBytes.String() {
		t.Errorf("key.Bytes() %+v != privateKeyBytes %+v", key.Bytes(), privateKeyBytes)
	}

	expectPrivateKey := PrivateKey{
		key:      privateKey,
		keyBytes: privateKeyBytes,
	}

	if !key.EqualsTo(expectPrivateKey) {
		t.Errorf("key %+v != expectPrivateKey %+v", key, expectPrivateKey)
	}

	if key.String() != privateKeyBytes.String() {
		t.Errorf("key.String() %+v != privateKeyBytes %+v", key.String(), privateKeyBytes)
	}
}
