// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"bytes"
	"path/filepath"
	"testing"
)

// go test -v -cover -run=^TestGenerateKeys$
func TestGenerateKeys(t *testing.T) {
	privateKey, publicKey, err := GenerateKeys(2048)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Public Key:", privateKey.key)
	t.Log("Private Key:", publicKey.key)
}

// go test -v -cover -run=^TestWriteReadPrivateKey$
func TestWriteReadPrivateKey(t *testing.T) {
	privateKey, _, err := GenerateKeys(2048)
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
	_, publicKey, err := GenerateKeys(2048)
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
	privateKey, _, err := GenerateKeys(2048)
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
	_, publicKey, err := GenerateKeys(2048)
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
