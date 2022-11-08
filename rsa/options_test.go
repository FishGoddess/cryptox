// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/FishGoddess/cryptox"
)

// go test -v -cover -run=^TestFromKeyOptions$
func TestFromKeyOptions(t *testing.T) {
	opts := []KeyOption{
		WithPrivateKeyEncoder(X509.PKCS8PrivateKeyEncoder),
		WithPrivateKeyDecoder(X509.PKCS8PrivateKeyDecoder),
		WithPublicKeyEncoder(X509.PKCS1PublicKeyEncoder),
		WithPublicKeyDecoder(X509.PKCS1PublicKeyDecoder),
	}

	cfg := fromKeyOptions(opts...)

	encoderPointer := fmt.Sprintf("%p", cfg.privateKeyEncoder)
	expectPointer := fmt.Sprintf("%p", X509.PKCS8PrivateKeyEncoder)

	if encoderPointer != expectPointer {
		t.Errorf("encoderPointer %s != expectPointer %s", encoderPointer, expectPointer)
	}

	decoderPointer := fmt.Sprintf("%p", cfg.privateKeyDecoder)
	expectPointer = fmt.Sprintf("%p", X509.PKCS8PrivateKeyDecoder)

	if decoderPointer != expectPointer {
		t.Errorf("decoderPointer %s != expectPointer %s", decoderPointer, expectPointer)
	}

	encoderPointer = fmt.Sprintf("%p", cfg.publicKeyEncoder)
	expectPointer = fmt.Sprintf("%p", X509.PKCS1PublicKeyEncoder)

	if encoderPointer != expectPointer {
		t.Errorf("encoderPointer %s != expectPointer %s", encoderPointer, expectPointer)
	}

	decoderPointer = fmt.Sprintf("%p", cfg.publicKeyDecoder)
	expectPointer = fmt.Sprintf("%p", X509.PKCS1PublicKeyDecoder)

	if decoderPointer != expectPointer {
		t.Errorf("decoderPointer %s != expectPointer %s", decoderPointer, expectPointer)
	}
}

// go test -v -cover -run=^TestWithPrivateKeyEncoder$
func TestWithPrivateKeyEncoder(t *testing.T) {
	cfg := &KeyConfig{privateKeyEncoder: nil}

	opt := WithPrivateKeyEncoder(X509.PKCS1PrivateKeyEncoder)
	opt.ApplyTo(cfg)

	encoderPointer := fmt.Sprintf("%p", cfg.privateKeyEncoder)
	expectPointer := fmt.Sprintf("%p", X509.PKCS1PrivateKeyEncoder)

	if encoderPointer != expectPointer {
		t.Errorf("encoderPointer %s != expectPointer %s", encoderPointer, expectPointer)
	}
}

// go test -v -cover -run=^TestWithPrivateKeyDecoder$
func TestWithPrivateKeyDecoder(t *testing.T) {
	cfg := &KeyConfig{privateKeyDecoder: nil}

	opt := WithPrivateKeyDecoder(X509.PKCS1PrivateKeyDecoder)
	opt.ApplyTo(cfg)

	decoderPointer := fmt.Sprintf("%p", cfg.privateKeyDecoder)
	expectPointer := fmt.Sprintf("%p", X509.PKCS1PrivateKeyDecoder)

	if decoderPointer != expectPointer {
		t.Errorf("decoderPointer %s != expectPointer %s", decoderPointer, expectPointer)
	}
}

// go test -v -cover -run=^TestWithPublicKeyEncoder$
func TestWithPublicKeyEncoder(t *testing.T) {
	cfg := &KeyConfig{publicKeyEncoder: nil}

	opt := WithPublicKeyEncoder(X509.PKIXPublicKeyEncoder)
	opt.ApplyTo(cfg)

	encoderPointer := fmt.Sprintf("%p", cfg.publicKeyEncoder)
	expectPointer := fmt.Sprintf("%p", X509.PKIXPublicKeyEncoder)

	if encoderPointer != expectPointer {
		t.Errorf("encoderPointer %s != expectPointer %s", encoderPointer, expectPointer)
	}
}

// go test -v -cover -run=^TestWithPublicKeyDecoder$
func TestWithPublicKeyDecoder(t *testing.T) {
	cfg := &KeyConfig{publicKeyDecoder: nil}

	opt := WithPublicKeyDecoder(X509.PKIXPublicKeyDecoder)
	opt.ApplyTo(cfg)

	decoderPointer := fmt.Sprintf("%p", cfg.publicKeyDecoder)
	expectPointer := fmt.Sprintf("%p", X509.PKIXPublicKeyDecoder)

	if decoderPointer != expectPointer {
		t.Errorf("decoderPointer %s != expectPointer %s", decoderPointer, expectPointer)
	}
}

// go test -v -cover -run=^TestWithRandom$
func TestWithRandom(t *testing.T) {
	cfg := &Config{random: nil}

	opt := WithRandom(rand.Reader)
	opt.ApplyTo(cfg)

	randomPointer := fmt.Sprintf("%p", cfg.random)
	expectPointer := fmt.Sprintf("%p", rand.Reader)

	if randomPointer != expectPointer {
		t.Errorf("randomPointer %s != expectPointer %s", randomPointer, expectPointer)
	}
}

// go test -v -cover -run=^TestWithHash$
func TestWithHash(t *testing.T) {
	cfg := &Config{random: nil}

	hash := cryptox.SHA256()
	opt := WithHash(hash)
	opt.ApplyTo(cfg)

	hashPointer := fmt.Sprintf("%p", cfg.hash)
	expectPointer := fmt.Sprintf("%p", hash)

	if hashPointer != expectPointer {
		t.Errorf("hashPointer %s != expectPointer %s", hashPointer, expectPointer)
	}
}

// go test -v -cover -run=^TestWithCryptoHash$
func TestWithCryptoHash(t *testing.T) {
	cfg := &Config{cryptoHash: 0}

	hash := crypto.SHA256
	opt := WithCryptoHash(hash)
	opt.ApplyTo(cfg)

	if cfg.cryptoHash != hash {
		t.Errorf("cfg.cryptoHash %d != hash %d", cfg.cryptoHash, hash)
	}
}
