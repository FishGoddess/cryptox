// Copyright 2023 FishGoddess. All rights reserved.
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
		t.Error(err)
	}

	t.Log("Public Key:", privateKey)
	t.Log("Private Key:", publicKey)
}

// go test -v -cover -run=^TestGeneratePrivateKey$
func TestGeneratePrivateKey(t *testing.T) {
	privateKey, err := GeneratePrivateKey(2048)
	if err != nil {
		t.Error(err)
	}

	t.Log("Private Key:", privateKey)
}

// go test -v -cover -run=^TestGeneratePublicKey$
func TestGeneratePublicKey(t *testing.T) {
	privateKey, publicKey1, err := GenerateKeys(2048)
	if err != nil {
		t.Error(err)
	}

	publicKey2, err := GeneratePublicKey(privateKey)
	if err != nil {
		t.Error(err)
	}

	if !publicKey2.EqualsTo(publicKey1) {
		t.Errorf("publicKey2 %+v != publicKey1 %+v", publicKey2, publicKey1)
	}
}

// go test -v -cover -run=^TestParsePrivateKey$
func TestParsePrivateKey(t *testing.T) {
	privateKey, err := GeneratePrivateKey(2048)
	if err != nil {
		t.Error(err)
	}

	parsedPrivateKey, err := ParsePrivateKey(privateKey.Bytes())
	if err != nil {
		t.Error(err)
	}

	if !parsedPrivateKey.EqualsTo(privateKey) {
		t.Errorf("parsedPrivateKey %+v != privateKey %+v", parsedPrivateKey, privateKey)
	}
}

// go test -v -cover -run=^TestParsePublicKey$
func TestParsePublicKey(t *testing.T) {
	privateKey, err := GeneratePrivateKey(2048)
	if err != nil {
		t.Error(err)
	}

	publicKey, err := GeneratePublicKey(privateKey)
	if err != nil {
		t.Error(err)
	}

	parsedPublicKey, err := ParsePublicKey(publicKey.Bytes())
	if err != nil {
		t.Error(err)
	}

	if !parsedPublicKey.EqualsTo(publicKey) {
		t.Errorf("parsedPublicKey %+v != publicKey %+v", parsedPublicKey, publicKey)
	}
}

// go test -v -cover -run=^TestReadPrivateKey$
func TestReadPrivateKey(t *testing.T) {
	privateKey, err := GeneratePrivateKey(2048)
	if err != nil {
		t.Error(err)
	}

	reader := bytes.NewReader(privateKey.Bytes())

	readPrivateKey, err := ReadPrivateKey(reader)
	if err != nil {
		t.Error(err)
	}

	if !readPrivateKey.EqualsTo(privateKey) {
		t.Errorf("readPrivateKey %+v != privateKey %+v", readPrivateKey, privateKey)
	}
}

// go test -v -cover -run=^TestReadPublicKey$
func TestReadPublicKey(t *testing.T) {
	privateKey, err := GeneratePrivateKey(2048)
	if err != nil {
		t.Error(err)
	}

	publicKey, err := GeneratePublicKey(privateKey)
	if err != nil {
		t.Error(err)
	}

	reader := bytes.NewReader(publicKey.Bytes())

	readPublicKey, err := ReadPublicKey(reader)
	if err != nil {
		t.Error(err)
	}

	if !readPublicKey.EqualsTo(publicKey) {
		t.Errorf("readPublicKey %+v != publicKey %+v", readPublicKey, publicKey)
	}
}

// go test -v -cover -run=^TestLoadPrivateKey$
func TestLoadPrivateKey(t *testing.T) {
	privateKey, err := GeneratePrivateKey(2048)
	if err != nil {
		t.Error(err)
	}

	privateKeyFile := filepath.Join(t.TempDir(), "TestLoadPrivateKey.key")

	_, err = privateKey.Bytes().WriteToFile(privateKeyFile)
	if err != nil {
		t.Error(err)
	}

	loadedPrivateKey, err := LoadPrivateKey(privateKeyFile)
	if err != nil {
		t.Error(err)
	}

	if !loadedPrivateKey.EqualsTo(privateKey) {
		t.Errorf("loadedPrivateKey %+v != privateKey %+v", loadedPrivateKey, privateKey)
	}
}

// go test -v -cover -run=^TestLoadPublicKey$
func TestLoadPublicKey(t *testing.T) {
	privateKey, err := GeneratePrivateKey(2048)
	if err != nil {
		t.Error(err)
	}

	publicKey, err := GeneratePublicKey(privateKey)
	if err != nil {
		t.Error(err)
	}

	publicKeyFile := filepath.Join(t.TempDir(), "TestLoadPublicKey.pub")

	_, err = publicKey.Bytes().WriteToFile(publicKeyFile)
	if err != nil {
		t.Error(err)
	}

	loadedPublicKey, err := LoadPublicKey(publicKeyFile)
	if err != nil {
		t.Error(err)
	}

	if !loadedPublicKey.EqualsTo(publicKey) {
		t.Errorf("loadedPublicKey %+v != publicKey %+v", loadedPublicKey, publicKey)
	}
}

// go test -v -cover -run=^TestMustLoadPrivateKey$
func TestMustLoadPrivateKey(t *testing.T) {
	privateKey, err := GeneratePrivateKey(2048)
	if err != nil {
		t.Error(err)
	}

	privateKeyFile := filepath.Join(t.TempDir(), "TestMustLoadPrivateKey.key")

	_, err = privateKey.Bytes().WriteToFile(privateKeyFile)
	if err != nil {
		t.Error(err)
	}

	defer func() {
		if err := recover(); err != nil {
			t.Error(err)
		}
	}()

	loadedPrivateKey := MustLoadPrivateKey(privateKeyFile)

	if !loadedPrivateKey.EqualsTo(privateKey) {
		t.Errorf("loadedPrivateKey %+v != privateKey %+v", loadedPrivateKey, privateKey)
	}
}

// go test -v -cover -run=^TestMustLoadPublicKey$
func TestMustLoadPublicKey(t *testing.T) {
	privateKey, err := GeneratePrivateKey(2048)
	if err != nil {
		t.Error(err)
	}

	publicKey, err := GeneratePublicKey(privateKey)
	if err != nil {
		t.Error(err)
	}

	publicKeyFile := filepath.Join(t.TempDir(), "TestMustLoadPublicKey.pub")

	_, err = publicKey.Bytes().WriteToFile(publicKeyFile)
	if err != nil {
		t.Error(err)
	}

	defer func() {
		if err := recover(); err != nil {
			t.Error(err)
		}
	}()

	loadedPublicKey := MustLoadPublicKey(publicKeyFile)

	if !loadedPublicKey.EqualsTo(publicKey) {
		t.Errorf("loadedPublicKey %+v != publicKey %+v", loadedPublicKey, publicKey)
	}
}
