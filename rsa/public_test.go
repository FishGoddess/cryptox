// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/FishGoddess/cryptox"
)

func newTestPublicKey(t *testing.T) PublicKey {
	keyBytes := []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu0KvOo1/9owLI+GZuzlu
PmixfDEeNBA+t2qppsVT9xb4huZbwXwowNP6KU4vPpdF0KhHSmaFOf8IIXSoZ/xI
7bLxs10Te1fSqZInVuj912VLj/uwuK7OG1zfsN0mt8I2d+9zYzAGykh/U/skYALO
zvmfvamcQGHT1TuxOsQln3Eq0477VGmk53vTMOxEU033CUEabuNOiWlM8TsaDEqx
YWO3Two+rSNW4S48WTQhekhqtxxg0LhJfB/T9tCOmzuTln4oVk4peZW+CH0UJijt
d/2Ypx/Hyk0yXQgGtIKUN35avn2/ga56HOxGYumk22Q4Xv4OZOmevzPLyvRZDZMW
uwIDAQAB
-----END PUBLIC KEY-----`)

	publicKey, err := ParsePublicKey(keyBytes)
	if err != nil {
		t.Fatal(err)
	}

	return publicKey
}

// go test -v -cover -run=^TestPublicKey$
func TestPublicKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	publicKey := &privateKey.PublicKey

	publicKeyBytes, err := X509.PKIXPublicKeyEncoder(publicKey)
	if err != nil {
		t.Fatal(err)
	}

	key := newPublicKey(publicKey, publicKeyBytes)
	if key.key != publicKey {
		t.Fatalf("key.key %+v != publicKey %+v", key.key, publicKey)
	}

	if !bytes.Equal(key.keyBytes, publicKeyBytes) {
		t.Fatalf("key.keyBytes %+v != publicKeyBytes %+v", key.keyBytes, publicKeyBytes)
	}

	if key.Key() != publicKey {
		t.Fatalf("key.Key() %+v != publicKey %+v", key.Key(), publicKey)
	}

	if !bytes.Equal(key.Bytes(), publicKeyBytes) {
		t.Fatalf("key.Bytes() %+v != publicKeyBytes %+v", key.Bytes(), publicKeyBytes)
	}

	expectPublicKey := PublicKey{
		key:      publicKey,
		keyBytes: publicKeyBytes,
	}

	if !key.EqualsTo(expectPublicKey) {
		t.Fatalf("key %+v != expectPublicKey %+v", key, expectPublicKey)
	}

	if key.String() != string(publicKeyBytes) {
		t.Fatalf("key.String() %s != publicKeyBytes %s", key.String(), publicKeyBytes)
	}
}

// go test -v -cover -run=^TestPublicKeyEncryptPKCS1v15$
func TestPublicKeyEncryptPKCS1v15(t *testing.T) {
	publicKey := newTestPublicKey(t)
	privateKey := newTestPrivateKey(t)

	cases := []string{
		"", "123", "你好，世界",
	}

	for _, msg := range cases {
		encrypted, err := publicKey.EncryptPKCS1v15(cryptox.Bytes(msg))
		if err != nil {
			t.Fatal(err)
		}

		decrypted, err := privateKey.DecryptPKCS1v15(encrypted)
		if err != nil {
			t.Fatal(err)
		}

		if string(decrypted) != msg {
			t.Fatalf("decrypted %s != msg %s", decrypted, msg)
		}
	}
}

// go test -v -cover -run=^TestPublicKeyEncryptOAEP$
func TestPublicKeyEncryptOAEP(t *testing.T) {
	publicKey := newTestPublicKey(t)
	privateKey := newTestPrivateKey(t)

	cases := []string{
		"", "123", "你好，世界",
	}

	for _, msg := range cases {
		encrypted, err := publicKey.EncryptOAEP(cryptox.Bytes(msg), cryptox.Bytes(msg))
		if err != nil {
			t.Fatal(err)
		}

		decrypted, err := privateKey.DecryptOAEP(encrypted, cryptox.Bytes(msg))
		if err != nil {
			t.Fatal(err)
		}

		if string(decrypted) != msg {
			t.Fatalf("decrypted %s != msg %s", decrypted, msg)
		}
	}
}

// go test -v -cover -run=^TestPublicKeyVerifyPKCS1v15$
func TestPublicKeyVerifyPKCS1v15(t *testing.T) {
	publicKey := newTestPublicKey(t)
	privateKey := newTestPrivateKey(t)

	cases := []string{
		"d41d8cd98f00b204e9800998ecf8427e", "202cb962ac59075b964b07152d234b70", "dbefd3ada018615b35588a01e216ae6e",
	}

	for _, msg := range cases {
		signature, err := privateKey.SignPKCS1v15(cryptox.Bytes(msg))
		if err != nil {
			t.Fatal(err)
		}

		err = publicKey.VerifyPKCS1v15(cryptox.Bytes(msg), signature)
		if err != nil {
			t.Fatal(err)
		}
	}
}

// go test -v -cover -run=^TestPublicKeyVerifyPSS$
func TestPublicKeyVerifyPSS(t *testing.T) {
	publicKey := newTestPublicKey(t)
	privateKey := newTestPrivateKey(t)

	cases := []string{
		"d41d8cd98f00b204e9800998ecf8427e", "202cb962ac59075b964b07152d234b70", "dbefd3ada018615b35588a01e216ae6e",
	}

	for _, msg := range cases {
		signature, err := privateKey.SignPSS(cryptox.Bytes(msg), 0)
		if err != nil {
			t.Fatal(err)
		}

		err = publicKey.VerifyPSS(cryptox.Bytes(msg), signature, 0)
		if err != nil {
			t.Fatal(err)
		}
	}
}
