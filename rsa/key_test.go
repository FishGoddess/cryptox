// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"
)

// go test -v -cover -run=^TestWithPrivateKeyEncoder$
func TestWithPrivateKeyEncoder(t *testing.T) {
	generator := &KeyGenerator{privateKeyEncoder: nil}

	opt := WithPrivateKeyEncoder(PKCS1PrivateKeyEncoder)
	opt.ApplyTo(generator)

	encoderPointer := fmt.Sprintf("%p", generator.privateKeyEncoder)
	expectPointer := fmt.Sprintf("%p", PKCS1PrivateKeyEncoder)

	if encoderPointer != expectPointer {
		t.Errorf("encoderPointer %s != expectPointer %s", encoderPointer, expectPointer)
	}
}

// go test -v -cover -run=^TestWithPrivateKeyDecoder$
func TestWithPrivateKeyDecoder(t *testing.T) {
	generator := &KeyGenerator{privateKeyDecoder: nil}

	opt := WithPrivateKeyDecoder(PKCS1PrivateKeyDecoder)
	opt.ApplyTo(generator)

	decoderPointer := fmt.Sprintf("%p", generator.privateKeyDecoder)
	expectPointer := fmt.Sprintf("%p", PKCS1PrivateKeyDecoder)

	if decoderPointer != expectPointer {
		t.Errorf("decoderPointer %s != expectPointer %s", decoderPointer, expectPointer)
	}
}

// go test -v -cover -run=^TestWithPublicKeyEncoder$
func TestWithPublicKeyEncoder(t *testing.T) {
	generator := &KeyGenerator{publicKeyEncoder: nil}

	opt := WithPublicKeyEncoder(PKIXPublicKeyEncoder)
	opt.ApplyTo(generator)

	encoderPointer := fmt.Sprintf("%p", generator.publicKeyEncoder)
	expectPointer := fmt.Sprintf("%p", PKIXPublicKeyEncoder)

	if encoderPointer != expectPointer {
		t.Errorf("encoderPointer %s != expectPointer %s", encoderPointer, expectPointer)
	}
}

// go test -v -cover -run=^TestWithPublicKeyDecoder$
func TestWithPublicKeyDecoder(t *testing.T) {
	generator := &KeyGenerator{publicKeyDecoder: nil}

	opt := WithPublicKeyDecoder(PKIXPublicKeyDecoder)
	opt.ApplyTo(generator)

	decoderPointer := fmt.Sprintf("%p", generator.publicKeyDecoder)
	expectPointer := fmt.Sprintf("%p", PKIXPublicKeyDecoder)

	if decoderPointer != expectPointer {
		t.Errorf("decoderPointer %s != expectPointer %s", decoderPointer, expectPointer)
	}
}

// go test -v -cover -run=^TestNewKeyGenerator$
func TestNewKeyGenerator(t *testing.T) {
	generator := NewKeyGenerator()

	coderPointer := fmt.Sprintf("%p", generator.privateKeyEncoder)
	expectPointer := fmt.Sprintf("%p", PKCS1PrivateKeyEncoder)

	if coderPointer != expectPointer {
		t.Errorf("coderPointer %s != expectPointer %s", coderPointer, expectPointer)
	}

	coderPointer = fmt.Sprintf("%p", generator.privateKeyDecoder)
	expectPointer = fmt.Sprintf("%p", PKCS1PrivateKeyDecoder)

	if coderPointer != expectPointer {
		t.Errorf("coderPointer %s != expectPointer %s", coderPointer, expectPointer)
	}

	coderPointer = fmt.Sprintf("%p", generator.publicKeyEncoder)
	expectPointer = fmt.Sprintf("%p", PKIXPublicKeyEncoder)

	if coderPointer != expectPointer {
		t.Errorf("coderPointer %s != expectPointer %s", coderPointer, expectPointer)
	}

	coderPointer = fmt.Sprintf("%p", generator.publicKeyDecoder)
	expectPointer = fmt.Sprintf("%p", PKIXPublicKeyDecoder)

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

	privateKey, privateKeyBytes, err := generator.GeneratePrivateKey(2048)
	if err != nil {
		t.Error(err)
	}

	_, publicKeyBytes1, err := generator.GeneratePublicKey(privateKey)
	if err != nil {
		t.Error(err)
	}

	_, publicKeyBytes2, err := generator.GeneratePublicKeyFromPem(privateKeyBytes)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(publicKeyBytes1, publicKeyBytes2) {
		t.Errorf("publicKeyBytes1 %+v != publicKeyBytes2 %+v", publicKeyBytes1, publicKeyBytes2)
	}
}

// go test -v -cover -run=^TestKeyGeneratorGeneratePublicKeyFromPem$
func TestKeyGeneratorGeneratePublicKeyFromPem(t *testing.T) {
	generator := NewKeyGenerator()

	key, err := generator.GenerateKey(2048)
	if err != nil {
		t.Error(err)
	}

	_, publicKeyBytes, err := generator.GeneratePublicKeyFromPem(key.Private)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(key.Public, publicKeyBytes) {
		t.Errorf("key.Public %+v != publicKeyBytes %+v", key.Public, publicKeyBytes)
	}
}

// go test -v -cover -run=^TestKeyGeneratorParsePrivateKey$
func TestKeyGeneratorParsePrivateKey(t *testing.T) {
	generator := NewKeyGenerator()

	privateKey, privateKeyBytes, err := generator.GeneratePrivateKey(2048)
	if err != nil {
		t.Error(err)
	}

	parsedPrivateKey, err := generator.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		t.Error(err)
	}

	if !parsedPrivateKey.Equal(privateKey) {
		t.Errorf("parsedPrivateKey %+v != privateKey %+v", parsedPrivateKey, privateKey)
	}
}

// go test -v -cover -run=^TestKeyGeneratorParsePublicKey$
func TestKeyGeneratorParsePublicKey(t *testing.T) {
	generator := NewKeyGenerator()

	privateKey, _, err := generator.GeneratePrivateKey(2048)
	if err != nil {
		t.Error(err)
	}

	publicKey, publicKeyBytes, err := generator.GeneratePublicKey(privateKey)
	if err != nil {
		t.Error(err)
	}

	parsedPublicKey, err := generator.ParsePublicKey(publicKeyBytes)
	if err != nil {
		t.Error(err)
	}

	if !parsedPublicKey.Equal(publicKey) {
		t.Errorf("parsedPublicKey %+v != publicKey %+v", parsedPublicKey, publicKey)
	}
}

// go test -v -cover -run=^TestKeyWriteTo$
func TestKeyWriteTo(t *testing.T) {
	generator := NewKeyGenerator()

	key, err := generator.GenerateKey(2048)
	if err != nil {
		t.Error(err)
	}

	var privateBuffer, publicBuffer bytes.Buffer
	n, err := key.WriteTo(&privateBuffer, &publicBuffer)
	if err != nil {
		t.Error(err)
	}

	if n != len(key.Private)+len(key.Public) {
		t.Errorf("n %d != len(key.Private) %d + len(key.Public) %d", n, len(key.Private), len(key.Public))
	}

	if !bytes.Equal(key.Private, privateBuffer.Bytes()) {
		t.Errorf("key.Private %+v != privateBuffer.Bytes() %+v", key.Private, privateBuffer.Bytes())
	}

	if !bytes.Equal(key.Public, publicBuffer.Bytes()) {
		t.Errorf("key.Public %+v != publicBuffer.Bytes() %+v", key.Public, publicBuffer.Bytes())
	}
}

// go test -v -cover -run=^TestKeyWriteToFile$
func TestKeyWriteToFile(t *testing.T) {
	generator := NewKeyGenerator()

	key, err := generator.GenerateKey(2048)
	if err != nil {
		t.Error(err)
	}

	privatePath := filepath.Join(t.TempDir(), t.Name()+".pem")
	publicPath := filepath.Join(t.TempDir(), t.Name()+".pub")
	t.Log("private path:", privatePath)
	t.Log("public path:", publicPath)

	n, err := key.WriteToFile(privatePath, publicPath)
	if err != nil {
		t.Error(err)
	}

	if n != len(key.Private)+len(key.Public) {
		t.Errorf("n %d != len(key.Private) %d + len(key.Public) %d", n, len(key.Private), len(key.Public))
	}

	privateBytes, err := ioutil.ReadFile(privatePath)
	if err != nil {
		t.Error(err)
	}

	publicBytes, err := ioutil.ReadFile(publicPath)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(key.Private, privateBytes) {
		t.Errorf("key.Private %+v != privateBytes %+v", key.Private, privateBytes)
	}

	if !bytes.Equal(key.Public, publicBytes) {
		t.Errorf("key.Public %+v != publicBytes %+v", key.Public, publicBytes)
	}
}
