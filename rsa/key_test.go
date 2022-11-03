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

// go test -v -cover -run=^TestKeyWritePrivateTo$
func TestKeyWritePrivateTo(t *testing.T) {
	key := Key{
		PrivateBytes: []byte("private"),
	}

	var privateBuffer bytes.Buffer
	n, err := key.WritePrivateTo(&privateBuffer)
	if err != nil {
		t.Error(err)
	}

	if n != len(key.PrivateBytes) {
		t.Errorf("n %d != len(key.PrivateBytes) %d", n, len(key.PrivateBytes))
	}

	if !bytes.Equal(key.PrivateBytes, privateBuffer.Bytes()) {
		t.Errorf("key.PrivateBytes %+v != privateBuffer.Bytes() %+v", key.PrivateBytes, privateBuffer.Bytes())
	}
}

// go test -v -cover -run=^TestKeyWritePublicTo$
func TestKeyWritePublicTo(t *testing.T) {
	key := Key{
		PublicBytes: []byte("public"),
	}

	var publicBuffer bytes.Buffer
	n, err := key.WritePublicTo(&publicBuffer)
	if err != nil {
		t.Error(err)
	}

	if n != len(key.PublicBytes) {
		t.Errorf("n %d != len(key.PublicBytes) %d", n, len(key.PublicBytes))
	}

	if !bytes.Equal(key.PublicBytes, publicBuffer.Bytes()) {
		t.Errorf("key.PublicBytes %+v != publicBuffer.Bytes() %+v", key.PublicBytes, publicBuffer.Bytes())
	}
}

// go test -v -cover -run=^TestKeyWriteTo$
func TestKeyWriteTo(t *testing.T) {
	key := Key{
		PrivateBytes: []byte("private"),
		PublicBytes:  []byte("public"),
	}

	var privateBuffer, publicBuffer bytes.Buffer
	n, err := key.WriteTo(&privateBuffer, &publicBuffer)
	if err != nil {
		t.Error(err)
	}

	if n != len(key.PrivateBytes)+len(key.PublicBytes) {
		t.Errorf("n %d != len(key.PrivateBytes) %d + len(key.PublicBytes) %d", n, len(key.PrivateBytes), len(key.PublicBytes))
	}

	if !bytes.Equal(key.PrivateBytes, privateBuffer.Bytes()) {
		t.Errorf("key.PrivateBytes %+v != privateBuffer.Bytes() %+v", key.PrivateBytes, privateBuffer.Bytes())
	}

	if !bytes.Equal(key.PublicBytes, publicBuffer.Bytes()) {
		t.Errorf("key.PublicBytes %+v != publicBuffer.Bytes() %+v", key.PublicBytes, publicBuffer.Bytes())
	}
}

// go test -v -cover -run=^TestKeyWritePrivateToFile$
func TestKeyWritePrivateToFile(t *testing.T) {
	key := Key{
		PrivateBytes: []byte("private"),
	}

	privatePath := filepath.Join(t.TempDir(), t.Name()+".key")
	t.Log("private path:", privatePath)

	n, err := key.WritePrivateToFile(privatePath)
	if err != nil {
		t.Error(err)
	}

	if n != len(key.PrivateBytes) {
		t.Errorf("n %d != len(key.PrivateBytes) %d", n, len(key.PrivateBytes))
	}

	privateBytes, err := ioutil.ReadFile(privatePath)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(key.PrivateBytes, privateBytes) {
		t.Errorf("key.PrivateBytes %+v != privateBytes %+v", key.PrivateBytes, privateBytes)
	}
}

// go test -v -cover -run=^TestKeyWritePublicToFile$
func TestKeyWritePublicToFile(t *testing.T) {
	key := Key{
		PublicBytes: []byte("public"),
	}

	publicPath := filepath.Join(t.TempDir(), t.Name()+".pub")
	t.Log("public path:", publicPath)

	n, err := key.WritePublicToFile(publicPath)
	if err != nil {
		t.Error(err)
	}

	if n != len(key.PublicBytes) {
		t.Errorf("n %d != len(key.PublicBytes) %d", n, len(key.PublicBytes))
	}

	publicBytes, err := ioutil.ReadFile(publicPath)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(key.PublicBytes, publicBytes) {
		t.Errorf("key.PublicBytes %+v != publicBytes %+v", key.PublicBytes, publicBytes)
	}
}

// go test -v -cover -run=^TestKeyWriteToFile$
func TestKeyWriteToFile(t *testing.T) {
	key := Key{
		PrivateBytes: []byte("private"),
		PublicBytes:  []byte("public"),
	}

	privatePath := filepath.Join(t.TempDir(), t.Name()+".key")
	publicPath := filepath.Join(t.TempDir(), t.Name()+".pub")
	t.Log("private path:", privatePath)
	t.Log("public path:", publicPath)

	n, err := key.WriteToFile(privatePath, publicPath)
	if err != nil {
		t.Error(err)
	}

	if n != len(key.PrivateBytes)+len(key.PublicBytes) {
		t.Errorf("n %d != len(key.PrivateBytes) %d + len(key.PublicBytes) %d", n, len(key.PrivateBytes), len(key.PublicBytes))
	}

	privateBytes, err := ioutil.ReadFile(privatePath)
	if err != nil {
		t.Error(err)
	}

	publicBytes, err := ioutil.ReadFile(publicPath)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(key.PrivateBytes, privateBytes) {
		t.Errorf("key.PrivateBytes %+v != privateBytes %+v", key.PrivateBytes, privateBytes)
	}

	if !bytes.Equal(key.PublicBytes, publicBytes) {
		t.Errorf("key.PublicBytes %+v != publicBytes %+v", key.PublicBytes, publicBytes)
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
