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
	expectPointer := fmt.Sprintf("%p", X509.PKCS1PrivateKeyDecoder)

	if coderPointer != expectPointer {
		t.Errorf("coderPointer %s != expectPointer %s", coderPointer, expectPointer)
	}

	coderPointer = fmt.Sprintf("%p", loader.publicKeyDecoder)
	expectPointer = fmt.Sprintf("%p", X509.PKIXPublicKeyDecoder)

	if coderPointer != expectPointer {
		t.Errorf("coderPointer %s != expectPointer %s", coderPointer, expectPointer)
	}
}

// go test -v -cover -run=^TestKeyLoaderParsePrivateKey$
func TestKeyLoaderParsePrivateKey(t *testing.T) {
	generator := NewKeyGenerator()
	loader := NewKeyLoader()

	privateKey, err := generator.GeneratePrivateKey(2048)
	if err != nil {
		t.Error(err)
	}

	parsedPrivateKey, err := loader.ParsePrivateKey(privateKey.Encoded())
	if err != nil {
		t.Error(err)
	}

	if !parsedPrivateKey.Equal(privateKey.Key()) {
		t.Errorf("parsedPrivateKey %+v != privateKey %+v", parsedPrivateKey, privateKey)
	}
}

// go test -v -cover -run=^TestKeyLoaderParsePublicKey$
func TestKeyLoaderParsePublicKey(t *testing.T) {
	generator := NewKeyGenerator()
	loader := NewKeyLoader()

	privateKey, err := generator.GeneratePrivateKey(2048)
	if err != nil {
		t.Error(err)
	}

	publicKey, err := generator.GeneratePublicKey(privateKey)
	if err != nil {
		t.Error(err)
	}

	parsedPublicKey, err := loader.ParsePublicKey(publicKey.Encoded())
	if err != nil {
		t.Error(err)
	}

	if !parsedPublicKey.Equal(publicKey.Key()) {
		t.Errorf("parsedPublicKey %+v != publicKey %+v", parsedPublicKey, publicKey)
	}
}

// TODO 测试 loader 的几个 load 方法
