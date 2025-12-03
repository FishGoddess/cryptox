// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"bytes"
	"slices"
	"testing"

	"github.com/FishGoddess/cryptox/bytes/encoding"
)

func newTestPublicKey() PublicKey {
	reader := bytes.NewReader([]byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp6Ap2KrXXMaNmc3K6ZHx
2IPrP4Bq5be1sP/4ASX3AmeuJbOHw+CNAQ/l3tFh7k+aaKMOgsspdtMq72Nd6KpU
a9OW7Jz6btmTohD34gEG/PfMYGGMKA8CxJO+VLtaMed7p4YWW0SjZ3tVdUDGBacQ
IHgDMTC9PWZhKj6d6tATWXI2amqv9rph1TgTq6q0SWRuwD2aYsQL8G0SicxC6uNL
NMw+hAqL2ZP91lRfARHK5sm5p257NWPPabVxWSEFSj6h11CvflWyIimbFPlCqWNv
ViozpBC3EqxuxzGWyF4r87MBp+XNA7JF0P0281eVjcaVtOzqdLN8vRu5/pE3MrWR
EwIDAQAB
-----END PUBLIC KEY-----`))

	publicKey, err := ReadPublicKey(reader)
	if err != nil {
		panic(err)
	}

	return publicKey
}

// go test -v -cover -run=^TestEncryptDecryptPKCS1v15$
func TestEncryptDecryptPKCS1v15(t *testing.T) {
	privateKey := newTestPrivateKey()
	publicKey := newTestPublicKey()

	type testCase struct {
		Data              []byte
		EncryptData       []byte
		EncryptDataHex    []byte
		EncryptDataBase64 []byte
	}

	testCases := []testCase{
		{
			Data:              []byte(""),
			EncryptData:       []byte(""),
			EncryptDataHex:    []byte(""),
			EncryptDataBase64: []byte(""),
		},
		{
			Data:              []byte("123"),
			EncryptData:       []byte(""),
			EncryptDataHex:    []byte(""),
			EncryptDataBase64: []byte(""),
		},
		{
			Data:              []byte("你好，世界"),
			EncryptData:       []byte(""),
			EncryptDataHex:    []byte(""),
			EncryptDataBase64: []byte(""),
		},
	}

	sessionKey := []byte("12345678876543211234567887654321")
	for _, testCase := range testCases {
		// None
		encrypted, err := publicKey.EncryptPKCS1v15(testCase.Data, encoding.None)
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(encrypted, testCase.EncryptData) {
			t.Fatalf("data %q: got %+v != expect %+v", testCase.Data, encrypted, testCase.EncryptData)
		}

		if err = privateKey.DecryptPKCS1v15SessionKey(encrypted, sessionKey, encoding.None); err != nil {
			t.Fatal(err)
		}

		decrypted, err := privateKey.DecryptPKCS1v15(encrypted, encoding.None)
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(decrypted, testCase.Data) {
			t.Fatalf("encrypted %q: got %+v != expect %+v", encrypted, decrypted, testCase.Data)
		}

		// Hex
		encrypted, err = publicKey.EncryptPKCS1v15(testCase.Data, encoding.Hex)
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(encrypted, testCase.EncryptDataHex) {
			t.Fatalf("data %q: got %+v != expect %+v", testCase.Data, encrypted, testCase.EncryptDataHex)
		}

		if err = privateKey.DecryptPKCS1v15SessionKey(encrypted, sessionKey, encoding.Hex); err != nil {
			t.Fatal(err)
		}

		if err = privateKey.DecryptPKCS1v15SessionKey(encrypted, sessionKey, encoding.None); err != nil {
			t.Fatal(err)
		}

		decrypted, err = privateKey.DecryptPKCS1v15(encrypted, encoding.Hex)
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(decrypted, testCase.Data) {
			t.Fatalf("encrypted %q: got %+v != expect %+v", encrypted, decrypted, testCase.Data)
		}

		// Base64
		encrypted, err = publicKey.EncryptPKCS1v15(testCase.Data, encoding.Base64)
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(encrypted, testCase.EncryptDataBase64) {
			t.Fatalf("data %q: got %+v != expect %+v", testCase.Data, encrypted, testCase.EncryptDataBase64)
		}

		if err = privateKey.DecryptPKCS1v15SessionKey(encrypted, sessionKey, encoding.Base64); err != nil {
			t.Fatal(err)
		}

		decrypted, err = privateKey.DecryptPKCS1v15(encrypted, encoding.Base64)
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(decrypted, testCase.Data) {
			t.Fatalf("encrypted %q: got %+v != expect %+v", encrypted, decrypted, testCase.Data)
		}
	}
}

// go test -v -cover -run=^TestEncryptDecryptOAEP$
func TestEncryptDecryptOAEP(t *testing.T) {
	privateKey := newTestPrivateKey()
	publicKey := newTestPublicKey()

	type testCase struct {
		Data              []byte
		EncryptData       []byte
		EncryptDataHex    []byte
		EncryptDataBase64 []byte
	}

	testCases := []testCase{
		{
			Data:              []byte(""),
			EncryptData:       []byte(""),
			EncryptDataHex:    []byte(""),
			EncryptDataBase64: []byte(""),
		},
		{
			Data:              []byte("123"),
			EncryptData:       []byte(""),
			EncryptDataHex:    []byte(""),
			EncryptDataBase64: []byte(""),
		},
		{
			Data:              []byte("你好，世界"),
			EncryptData:       []byte(""),
			EncryptDataHex:    []byte(""),
			EncryptDataBase64: []byte(""),
		},
	}

	label := []byte("label")
	for _, testCase := range testCases {
		// None
		encrypted, err := publicKey.EncryptOAEP(testCase.Data, label, encoding.None)
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(encrypted, testCase.EncryptData) {
			t.Fatalf("data %q: got %+v != expect %+v", testCase.Data, encrypted, testCase.EncryptData)
		}

		decrypted, err := privateKey.DecryptOAEP(encrypted, label, encoding.None)
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(decrypted, testCase.Data) {
			t.Fatalf("encrypted %q: got %+v != expect %+v", encrypted, decrypted, testCase.Data)
		}

		// Hex
		encrypted, err = publicKey.EncryptOAEP(testCase.Data, label, encoding.Hex)
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(encrypted, testCase.EncryptDataHex) {
			t.Fatalf("data %q: got %+v != expect %+v", testCase.Data, encrypted, testCase.EncryptDataHex)
		}

		decrypted, err = privateKey.DecryptOAEP(encrypted, label, encoding.Hex)
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(decrypted, testCase.Data) {
			t.Fatalf("encrypted %q: got %+v != expect %+v", encrypted, decrypted, testCase.Data)
		}

		// Base64
		encrypted, err = publicKey.EncryptOAEP(testCase.Data, label, encoding.Base64)
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(encrypted, testCase.EncryptDataBase64) {
			t.Fatalf("data %q: got %+v != expect %+v", testCase.Data, encrypted, testCase.EncryptDataBase64)
		}

		decrypted, err = privateKey.DecryptOAEP(encrypted, label, encoding.Base64)
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(decrypted, testCase.Data) {
			t.Fatalf("encrypted %q: got %+v != expect %+v", encrypted, decrypted, testCase.Data)
		}
	}
}
