// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto/rand"
	"fmt"
	"testing"
)

// go test -v -cover -run=^TestWithGeneratePrivateKeyEncoder$
func TestWithGeneratePrivateKeyEncoder(t *testing.T) {
	generator := &KeyGenerator{privateKeyEncoder: nil}

	opt := WithGeneratePrivateKeyEncoder(PKCS1PrivateKeyEncoder)
	opt.ApplyTo(generator)

	encoderPointer := fmt.Sprintf("%p", generator.privateKeyEncoder)
	expectPointer := fmt.Sprintf("%p", PKCS1PrivateKeyEncoder)

	if encoderPointer != expectPointer {
		t.Errorf("encoderPointer %s != expectPointer %s", encoderPointer, expectPointer)
	}
}

// go test -v -cover -run=^TestWithGeneratePublicKeyEncoder$
func TestWithGeneratePublicKeyEncoder(t *testing.T) {
	generator := &KeyGenerator{publicKeyEncoder: nil}

	opt := WithGeneratePublicKeyEncoder(PKIXPublicKeyEncoder)
	opt.ApplyTo(generator)

	encoderPointer := fmt.Sprintf("%p", generator.publicKeyEncoder)
	expectPointer := fmt.Sprintf("%p", PKIXPublicKeyEncoder)

	if encoderPointer != expectPointer {
		t.Errorf("encoderPointer %s != expectPointer %s", encoderPointer, expectPointer)
	}
}

// go test -v -cover -run=^TestWithGeneratePrivateKeyDecoder$
func TestWithGeneratePrivateKeyDecoder(t *testing.T) {
	generator := &KeyGenerator{privateKeyDecoder: nil}

	opt := WithGeneratePrivateKeyDecoder(PKCS1PrivateKeyDecoder)
	opt.ApplyTo(generator)

	decoderPointer := fmt.Sprintf("%p", generator.privateKeyDecoder)
	expectPointer := fmt.Sprintf("%p", PKCS1PrivateKeyDecoder)

	if decoderPointer != expectPointer {
		t.Errorf("decoderPointer %s != expectPointer %s", decoderPointer, expectPointer)
	}
}

// go test -v -cover -run=^TestWithLoadPrivateKeyDecoder$
func TestWithLoadPrivateKeyDecoder(t *testing.T) {
	loader := &KeyLoader{privateKeyDecoder: nil}

	opt := WithLoadPrivateKeyDecoder(PKCS1PrivateKeyDecoder)
	opt.ApplyTo(loader)

	decoderPointer := fmt.Sprintf("%p", loader.privateKeyDecoder)
	expectPointer := fmt.Sprintf("%p", PKCS1PrivateKeyDecoder)

	if decoderPointer != expectPointer {
		t.Errorf("decoderPointer %s != expectPointer %s", decoderPointer, expectPointer)
	}
}

// go test -v -cover -run=^TestWithLoadPublicKeyDecoder$
func TestWithLoadPublicKeyDecoder(t *testing.T) {
	loader := &KeyLoader{publicKeyDecoder: nil}

	opt := WithLoadPublicKeyDecoder(PKIXPublicKeyDecoder)
	opt.ApplyTo(loader)

	decoderPointer := fmt.Sprintf("%p", loader.publicKeyDecoder)
	expectPointer := fmt.Sprintf("%p", PKIXPublicKeyDecoder)

	if decoderPointer != expectPointer {
		t.Errorf("decoderPointer %s != expectPointer %s", decoderPointer, expectPointer)
	}
}

// go test -v -cover -run=^TestWithRandom$
func TestWithRandom(t *testing.T) {
	oaep := &RSA{random: nil}

	opt := WithRandom(rand.Reader)
	opt.ApplyTo(oaep)

	hashPointer := fmt.Sprintf("%p", oaep.random)
	expectPointer := fmt.Sprintf("%p", rand.Reader)

	if hashPointer != expectPointer {
		t.Errorf("hashPointer %s != expectPointer %s", hashPointer, expectPointer)
	}
}
