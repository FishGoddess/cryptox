// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package ed25519

import (
	"bytes"
	"path/filepath"
	"slices"
	"testing"
)

// go test -v -cover -run=^TestGenerateKeys$
func TestGenerateKeys(t *testing.T) {
	privateKey, publicKey, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Public Key:", privateKey.key)
	t.Log("Private Key:", publicKey.key)

	seed := []byte("12345678876543211234567887654321")

	privateKey1, publicKey1, err := GenerateKeys(WithKeySeed(seed))
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Public Key1:", privateKey1.key)
	t.Log("Private Key1:", publicKey1.key)

	privateKey2, publicKey2, err := GenerateKeys(WithKeySeed(seed))
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Public Key2:", privateKey2.key)
	t.Log("Private Key2:", publicKey2.key)

	if !slices.Equal(privateKey1.key, privateKey2.key) {
		t.Fatalf("got %s != expect %s", privateKey1.key, privateKey2.key)
	}

	if !slices.Equal(publicKey1.key, publicKey2.key) {
		t.Fatalf("got %s != expect %s", publicKey1.key, publicKey2.key)
	}
}

// go test -v -cover -run=^TestWriteReadPrivateKey$
func TestWriteReadPrivateKey(t *testing.T) {
	privateKey, _, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	buffer := bytes.NewBuffer(make([]byte, 0, 4096))

	err = WritePrivateKey(buffer, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	bufferKey, err := ReadPrivateKey(buffer)
	if err != nil {
		t.Fatal(err)
	}

	if !bufferKey.key.Equal(privateKey.key) {
		t.Fatalf("bufferKey %+v != privateKey %+v", bufferKey.key, privateKey.key)
	}
}

// go test -v -cover -run=^TestWriteReadPublicKey$
func TestWriteReadPublicKey(t *testing.T) {
	_, publicKey, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	buffer := bytes.NewBuffer(make([]byte, 0, 4096))

	err = WritePublicKey(buffer, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	bufferKey, err := ReadPublicKey(buffer)
	if err != nil {
		t.Fatal(err)
	}

	if !bufferKey.key.Equal(publicKey.key) {
		t.Fatalf("bufferKey %+v != publicKey %+v", bufferKey.key, publicKey.key)
	}
}

// go test -v -cover -run=^TestStoreLoadPrivateKey$
func TestStoreLoadPrivateKey(t *testing.T) {
	privateKey, _, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	file := filepath.Join(t.TempDir(), t.Name()+".key")

	err = StorePrivateKey(file, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	fileKey, err := LoadPrivateKey(file)
	if err != nil {
		t.Fatal(err)
	}

	if !fileKey.key.Equal(privateKey.key) {
		t.Fatalf("fileKey %+v != privateKey %+v", fileKey.key, privateKey.key)
	}
}

// go test -v -cover -run=^TestStoreLoadPublicKey$
func TestStoreLoadPublicKey(t *testing.T) {
	_, publicKey, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	file := filepath.Join(t.TempDir(), t.Name()+".key")

	err = StorePublicKey(file, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	fileKey, err := LoadPublicKey(file)
	if err != nil {
		t.Fatal(err)
	}

	if !fileKey.key.Equal(publicKey.key) {
		t.Fatalf("fileKey %+v != publicKey %+v", fileKey.key, publicKey.key)
	}
}
