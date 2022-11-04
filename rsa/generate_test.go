// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"fmt"
	"io/ioutil"
	"testing"
)

// go test -v -cover -run=^TestNewKeyGenerator$
func TestNewKeyGenerator(t *testing.T) {
	generator := NewKeyGenerator()

	coderPointer := fmt.Sprintf("%p", generator.privateKeyEncoder)
	expectPointer := fmt.Sprintf("%p", X509.PKCS1PrivateKeyEncoder)

	if coderPointer != expectPointer {
		t.Errorf("coderPointer %s != expectPointer %s", coderPointer, expectPointer)
	}

	coderPointer = fmt.Sprintf("%p", generator.publicKeyEncoder)
	expectPointer = fmt.Sprintf("%p", X509.PKIXPublicKeyEncoder)

	if coderPointer != expectPointer {
		t.Errorf("coderPointer %s != expectPointer %s", coderPointer, expectPointer)
	}

	coderPointer = fmt.Sprintf("%p", generator.privateKeyDecoder)
	expectPointer = fmt.Sprintf("%p", X509.PKCS1PrivateKeyDecoder)

	if coderPointer != expectPointer {
		t.Errorf("coderPointer %s != expectPointer %s", coderPointer, expectPointer)
	}
}

// go test -v -cover -run=^TestKeyGeneratorGenerateKey$
func TestKeyGeneratorGenerateKey(t *testing.T) {
	generator := NewKeyGenerator()

	privateKey, publicKey, err := generator.GenerateKeys(2048)
	if err != nil {
		t.Error(err)
	}

	t.Log("Public Key:", privateKey)
	t.Log("Private Key:", publicKey)
}

// go test -v -cover -run=^TestKeyGeneratorGeneratePrivateKey$
func TestKeyGeneratorGeneratePrivateKey(t *testing.T) {
	generator := NewKeyGenerator()

	privateKey, err := generator.GeneratePrivateKey(2048)
	if err != nil {
		t.Error(err)
	}

	t.Log("Private Key:", privateKey)
}

// go test -v -cover -run=^TestKeyGeneratorGeneratePublicKey$
func TestKeyGeneratorGeneratePublicKey(t *testing.T) {
	generator := NewKeyGenerator()

	privateKey, publicKey1, err := generator.GenerateKeys(2048)
	if err != nil {
		t.Error(err)
	}

	publicKey2, err := generator.GeneratePublicKey(privateKey)
	if err != nil {
		t.Error(err)
	}

	if !publicKey2.EqualsTo(publicKey1) {
		t.Errorf("publicKey2 %+v != publicKey1 %+v", publicKey2, publicKey1)
	}
}

// go test -v -cover -run=^TestKeyGeneratorGeneratePublicKeyFromFile$
func TestKeyGeneratorGeneratePublicKeyFromFile(t *testing.T) {
	generator := NewKeyGenerator()

	privateKey, publicKey1, err := generator.GenerateKeys(2048)
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

	_, err = privateKey.Encoded().WriteToFile(privateKeyFile.Name())
	if err != nil {
		t.Error(err)
	}

	publicKey2, err := generator.GeneratePublicKeyFromFile(privateKeyFile.Name())
	if err != nil {
		t.Error(err)
	}

	if !publicKey2.EqualsTo(publicKey1) {
		t.Errorf("publicKey2 %+v != publicKey1 %+v", publicKey2, publicKey1)
	}
}
