// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package ecc

import (
	"bytes"
	"path/filepath"
	"testing"
)

// go test -v -cover -run=^TestGenerateKeys$
func TestGenerateKeys(t *testing.T) {
	privateKey, publicKey, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Public Key:", privateKey)
	t.Log("Private Key:", publicKey)
}

// go test -v -cover -run=^TestGeneratePrivateKey$
func TestGeneratePrivateKey(t *testing.T) {
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Private Key:", privateKey)
}

// go test -v -cover -run=^TestGeneratePublicKey$
func TestGeneratePublicKey(t *testing.T) {
	privateKey, publicKey1, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	publicKey2, err := GeneratePublicKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	if !publicKey2.EqualsTo(publicKey1) {
		t.Fatalf("publicKey2 %+v != publicKey1 %+v", publicKey2, publicKey1)
	}
}

// go test -v -cover -run=^TestParsePrivateKey$
func TestParsePrivateKey(t *testing.T) {
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	parsedPrivateKey, err := ParsePrivateKey(privateKey.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	if !parsedPrivateKey.EqualsTo(privateKey) {
		t.Fatalf("parsedPrivateKey %+v != privateKey %+v", parsedPrivateKey, privateKey)
	}
}

// go test -v -cover -run=^TestParsePublicKey$
func TestParsePublicKey(t *testing.T) {
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := GeneratePublicKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	parsedPublicKey, err := ParsePublicKey(publicKey.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	if !parsedPublicKey.EqualsTo(publicKey) {
		t.Fatalf("parsedPublicKey %+v != publicKey %+v", parsedPublicKey, publicKey)
	}
}

// go test -v -cover -run=^TestReadPrivateKey$
func TestReadPrivateKey(t *testing.T) {
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	reader := bytes.NewReader(privateKey.Bytes())

	readPrivateKey, err := ReadPrivateKey(reader)
	if err != nil {
		t.Fatal(err)
	}

	if !readPrivateKey.EqualsTo(privateKey) {
		t.Fatalf("readPrivateKey %+v != privateKey %+v", readPrivateKey, privateKey)
	}
}

// go test -v -cover -run=^TestReadPublicKey$
func TestReadPublicKey(t *testing.T) {
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := GeneratePublicKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	reader := bytes.NewReader(publicKey.Bytes())

	readPublicKey, err := ReadPublicKey(reader)
	if err != nil {
		t.Fatal(err)
	}

	if !readPublicKey.EqualsTo(publicKey) {
		t.Fatalf("readPublicKey %+v != publicKey %+v", readPublicKey, publicKey)
	}
}

// go test -v -cover -run=^TestLoadPrivateKey$
func TestLoadPrivateKey(t *testing.T) {
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	privateKeyFile := filepath.Join(t.TempDir(), "TestLoadPrivateKey.key")

	_, err = privateKey.Bytes().WriteToFile(privateKeyFile)
	if err != nil {
		t.Fatal(err)
	}

	loadedPrivateKey, err := LoadPrivateKey(privateKeyFile)
	if err != nil {
		t.Fatal(err)
	}

	if !loadedPrivateKey.EqualsTo(privateKey) {
		t.Fatalf("loadedPrivateKey %+v != privateKey %+v", loadedPrivateKey, privateKey)
	}
}

// go test -v -cover -run=^TestLoadPublicKey$
func TestLoadPublicKey(t *testing.T) {
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := GeneratePublicKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	publicKeyFile := filepath.Join(t.TempDir(), "TestLoadPublicKey.pub")

	_, err = publicKey.Bytes().WriteToFile(publicKeyFile)
	if err != nil {
		t.Fatal(err)
	}

	loadedPublicKey, err := LoadPublicKey(publicKeyFile)
	if err != nil {
		t.Fatal(err)
	}

	if !loadedPublicKey.EqualsTo(publicKey) {
		t.Fatalf("loadedPublicKey %+v != publicKey %+v", loadedPublicKey, publicKey)
	}
}

// go test -v -cover -run=^TestMustLoadPrivateKey$
func TestMustLoadPrivateKey(t *testing.T) {
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	privateKeyFile := filepath.Join(t.TempDir(), "TestMustLoadPrivateKey.key")

	_, err = privateKey.Bytes().WriteToFile(privateKeyFile)
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		if err := recover(); err != nil {
			t.Fatal(err)
		}
	}()

	loadedPrivateKey := MustLoadPrivateKey(privateKeyFile)

	if !loadedPrivateKey.EqualsTo(privateKey) {
		t.Fatalf("loadedPrivateKey %+v != privateKey %+v", loadedPrivateKey, privateKey)
	}
}

// go test -v -cover -run=^TestMustLoadPublicKey$
func TestMustLoadPublicKey(t *testing.T) {
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := GeneratePublicKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	publicKeyFile := filepath.Join(t.TempDir(), "TestMustLoadPublicKey.pub")

	_, err = publicKey.Bytes().WriteToFile(publicKeyFile)
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		if err := recover(); err != nil {
			t.Fatal(err)
		}
	}()

	loadedPublicKey := MustLoadPublicKey(publicKeyFile)

	if !loadedPublicKey.EqualsTo(publicKey) {
		t.Fatalf("loadedPublicKey %+v != publicKey %+v", loadedPublicKey, publicKey)
	}
}
