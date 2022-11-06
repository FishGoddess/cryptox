// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"bytes"
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
