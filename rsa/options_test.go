// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/FishGoddess/cryptox/bytes/encoding"
	"github.com/FishGoddess/cryptox/x509"
)

// go test -v -cover -run=^TestKeyConfig$
func TestKeyConfig(t *testing.T) {
	opts := []KeyOption{
		WithKeyRandom(rand.Reader),
		WithKeyEncodePrivate(x509.EncodePrivateKeyPKCS8),
		WithKeyEncodePublic(x509.EncodePublicKeyPKIX),
		WithKeyDecodePrivate(x509.DecodePrivateKeyPKCS8),
		WithKeyDecodePublic(x509.DecodePublicKeyPKIX),
	}

	conf := newKeyConfig().Apply(opts...)

	got := fmt.Sprintf("%p", conf.random)
	expect := fmt.Sprintf("%p", rand.Reader)
	if got != expect {
		t.Fatalf("got %s != expect %s", got, expect)
	}

	got = fmt.Sprintf("%p", conf.encodePrivateKey)
	expect = fmt.Sprintf("%p", x509.EncodePrivateKeyPKCS8[*rsa.PrivateKey])
	if got != expect {
		t.Fatalf("got %s != expect %s", got, expect)
	}

	got = fmt.Sprintf("%p", conf.encodePublicKey)
	expect = fmt.Sprintf("%p", x509.EncodePublicKeyPKIX[*rsa.PublicKey])
	if got != expect {
		t.Fatalf("got %s != expect %s", got, expect)
	}

	got = fmt.Sprintf("%p", conf.decodePrivateKey)
	expect = fmt.Sprintf("%p", x509.DecodePrivateKeyPKCS8[*rsa.PrivateKey])
	if got != expect {
		t.Fatalf("got %s != expect %s", got, expect)
	}

	got = fmt.Sprintf("%p", conf.decodePublicKey)
	expect = fmt.Sprintf("%p", x509.DecodePublicKeyPKIX[*rsa.PublicKey])
	if got != expect {
		t.Fatalf("got %s != expect %s", got, expect)
	}
}

// go test -v -cover -run=^TestConfig$
func TestConfig(t *testing.T) {
	hash := sha256.New()
	saltLength := 32

	opts := []Option{
		WithHex(),
		WithRandom(rand.Reader),
		WithHash(hash),
		WithCryptoHash(crypto.SHA256),
		WithSalt(saltLength),
	}

	conf := newConfig().Apply(opts...)

	got := fmt.Sprintf("%T", conf.encoding)
	expect := fmt.Sprintf("%T", encoding.Hex{})
	if got != expect {
		t.Fatalf("got %s != expect %s", got, expect)
	}

	conf.Apply(WithBase64())

	got = fmt.Sprintf("%T", conf.encoding)
	expect = fmt.Sprintf("%T", encoding.Base64{})
	if got != expect {
		t.Fatalf("got %s != expect %s", got, expect)
	}

	got = fmt.Sprintf("%p", conf.random)
	expect = fmt.Sprintf("%p", rand.Reader)
	if got != expect {
		t.Fatalf("got %s != expect %s", got, expect)
	}

	got = fmt.Sprintf("%p", conf.hash)
	expect = fmt.Sprintf("%p", hash)
	if got != expect {
		t.Fatalf("got %s != expect %s", got, expect)
	}

	if conf.cryptoHash != crypto.SHA256 {
		t.Fatalf("got %d != expect %d", conf.cryptoHash, crypto.SHA256)
	}

	if conf.saltLength != saltLength {
		t.Fatalf("got %d != expect %d", conf.saltLength, saltLength)
	}
}
