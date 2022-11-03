// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"testing"
)

// go test -v -cover -run=^TestNewKeyGenerator$
func TestNewKeyGenerator(t *testing.T) {
	generator := NewKeyGenerator()

	coderPointer := fmt.Sprintf("%p", generator.privateKeyEncoder)
	expectPointer := fmt.Sprintf("%p", PKCS1PrivateKeyEncoder)

	if coderPointer != expectPointer {
		t.Errorf("coderPointer %s != expectPointer %s", coderPointer, expectPointer)
	}

	coderPointer = fmt.Sprintf("%p", generator.publicKeyEncoder)
	expectPointer = fmt.Sprintf("%p", PKIXPublicKeyEncoder)

	if coderPointer != expectPointer {
		t.Errorf("coderPointer %s != expectPointer %s", coderPointer, expectPointer)
	}

	coderPointer = fmt.Sprintf("%p", generator.privateKeyDecoder)
	expectPointer = fmt.Sprintf("%p", PKCS1PrivateKeyDecoder)

	if coderPointer != expectPointer {
		t.Errorf("coderPointer %s != expectPointer %s", coderPointer, expectPointer)
	}
}

// go test -v -cover -run=^TestKeyGeneratorGenerateKey$
func TestKeyGeneratorGenerateKey(t *testing.T) {
	generator := NewKeyGenerator()

	key, err := generator.GenerateKey(2048)
	if err != nil {
		t.Error(err)
	}

	t.Log("Public Key:", key.Public)
	t.Log("Private Key:", key.Private)
}

// go test -v -cover -run=^TestKeyGeneratorGeneratePrivateKey$
func TestKeyGeneratorGeneratePrivateKey(t *testing.T) {
	generator := NewKeyGenerator()

	key, keyBytes, err := generator.GeneratePrivateKey(2048)
	if err != nil {
		t.Error(err)
	}

	t.Log("Private Key:", key)
	t.Log("Private Key Bytes:", keyBytes)
}

// go test -v -cover -run=^TestKeyGeneratorGeneratePublicKey$
func TestKeyGeneratorGeneratePublicKey(t *testing.T) {
	generator := NewKeyGenerator()

	privateKey, _, err := generator.GeneratePrivateKey(2048)
	if err != nil {
		t.Error(err)
	}

	publicKey, publicKeyBytes1, err := generator.GeneratePublicKey(privateKey)
	if err != nil {
		t.Error(err)
	}

	if !publicKey.Equal(&privateKey.PublicKey) {
		t.Errorf("publicKey %+v != privateKey.PublicKey %+v", publicKey, privateKey.PublicKey)
	}

	publicKeyBytes2, err := generator.publicKeyEncoder.Encode(&privateKey.PublicKey)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(publicKeyBytes1, publicKeyBytes2) {
		t.Errorf("publicKeyBytes1 %+v != publicKeyBytes2 %+v", publicKeyBytes1, publicKeyBytes2)
	}
}

// go test -v -cover -run=^TestKeyGeneratorGeneratePublicKeyFromFile$
func TestKeyGeneratorGeneratePublicKeyFromFile(t *testing.T) {
	generator := NewKeyGenerator()

	key, err := generator.GenerateKey(2048)
	if err != nil {
		t.Error(err)
	}

	privateKeyFile, err := ioutil.TempFile(t.TempDir(), t.Name()+".key")
	if err != nil {
		t.Error(err)
	}

	err = privateKeyFile.Close()
	if err != nil {
		t.Error(err)
	}

	_, err = key.WritePrivateToFile(privateKeyFile.Name())
	if err != nil {
		t.Error(err)
	}

	_, publicKeyBytes, err := generator.GeneratePublicKeyFromFile(privateKeyFile.Name())
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(key.PublicBytes, publicKeyBytes) {
		t.Errorf("key.PublicBytes %+v != publicKeyBytes %+v", key.PublicBytes, publicKeyBytes)
	}
}
