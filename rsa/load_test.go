// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"fmt"
	"testing"
)

// go test -v -cover -run=^TestNewKeyLoader$
func TestNewKeyLoader(t *testing.T) {
	loader := NewKeyLoader()

	coderPointer := fmt.Sprintf("%p", loader.privateKeyDecoder)
	expectPointer := fmt.Sprintf("%p", PKCS1PrivateKeyDecoder)

	if coderPointer != expectPointer {
		t.Errorf("coderPointer %s != expectPointer %s", coderPointer, expectPointer)
	}

	coderPointer = fmt.Sprintf("%p", loader.publicKeyDecoder)
	expectPointer = fmt.Sprintf("%p", PKIXPublicKeyDecoder)

	if coderPointer != expectPointer {
		t.Errorf("coderPointer %s != expectPointer %s", coderPointer, expectPointer)
	}
}

// go test -v -cover -run=^TestKeyLoaderParsePrivateKey$
func TestKeyLoaderParsePrivateKey(t *testing.T) {
	generator := NewKeyGenerator()
	loader := NewKeyLoader()

	privateKey, privateKeyBytes, err := generator.GeneratePrivateKey(2048)
	if err != nil {
		t.Error(err)
	}

	parsedPrivateKey, err := loader.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		t.Error(err)
	}

	if !parsedPrivateKey.Equal(privateKey) {
		t.Errorf("parsedPrivateKey %+v != privateKey %+v", parsedPrivateKey, privateKey)
	}
}

// go test -v -cover -run=^TestKeyLoaderParsePublicKey$
func TestKeyLoaderParsePublicKey(t *testing.T) {
	generator := NewKeyGenerator()
	loader := NewKeyLoader()

	privateKey, _, err := generator.GeneratePrivateKey(2048)
	if err != nil {
		t.Error(err)
	}

	publicKey, publicKeyBytes, err := generator.GeneratePublicKey(privateKey)
	if err != nil {
		t.Error(err)
	}

	parsedPublicKey, err := loader.ParsePublicKey(publicKeyBytes)
	if err != nil {
		t.Error(err)
	}

	if !parsedPublicKey.Equal(publicKey) {
		t.Errorf("parsedPublicKey %+v != publicKey %+v", parsedPublicKey, publicKey)
	}
}

// TODO 测试 loader 的几个 load 方法
