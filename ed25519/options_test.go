// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package ed25519

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"slices"
	"testing"

	"github.com/FishGoddess/cryptox/bytes/encoding"
	"github.com/FishGoddess/cryptox/x509"
)

// go test -v -cover -run=^TestKeyConfig$
func TestKeyConfig(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)

	opts := []KeyOption{
		WithKeySeed(seed),
		WithKeyRandom(rand.Reader),
		WithKeyEncodePrivate(x509.EncodePrivateKeyPKCS8),
		WithKeyEncodePublic(x509.EncodePublicKeyPKIX),
		WithKeyDecodePrivate(x509.DecodePrivateKeyPKCS8),
		WithKeyDecodePublic(x509.DecodePublicKeyPKIX),
	}

	conf := newKeyConfig().Apply(opts...)

	if !slices.Equal(conf.seed, seed) {
		t.Fatalf("got %s != expect %s", conf.seed, seed)
	}

	got := fmt.Sprintf("%p", conf.random)
	expect := fmt.Sprintf("%p", rand.Reader)
	if got != expect {
		t.Fatalf("got %s != expect %s", got, expect)
	}

	got = fmt.Sprintf("%p", conf.encodePrivateKey)
	expect = fmt.Sprintf("%p", x509.EncodePrivateKeyPKCS8[ed25519.PrivateKey])
	if got != expect {
		t.Fatalf("got %s != expect %s", got, expect)
	}

	got = fmt.Sprintf("%p", conf.encodePublicKey)
	expect = fmt.Sprintf("%p", x509.EncodePublicKeyPKIX[ed25519.PublicKey])
	if got != expect {
		t.Fatalf("got %s != expect %s", got, expect)
	}

	got = fmt.Sprintf("%p", conf.decodePrivateKey)
	expect = fmt.Sprintf("%p", x509.DecodePrivateKeyPKCS8[ed25519.PrivateKey])
	if got != expect {
		t.Fatalf("got %s != expect %s", got, expect)
	}

	got = fmt.Sprintf("%p", conf.decodePublicKey)
	expect = fmt.Sprintf("%p", x509.DecodePublicKeyPKIX[ed25519.PublicKey])
	if got != expect {
		t.Fatalf("got %s != expect %s", got, expect)
	}
}

// go test -v -cover -run=^TestConfig$
func TestConfig(t *testing.T) {
	context := "你好，世界"

	opts := []Option{
		WithHex(),
		WithCryptoHash(crypto.SHA256),
		WithContext(context),
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

	if conf.cryptoHash != crypto.SHA256 {
		t.Fatalf("got %d != expect %d", conf.cryptoHash, crypto.SHA256)
	}

	if conf.context != context {
		t.Fatalf("got %s != expect %s", conf.context, context)
	}
}
