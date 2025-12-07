// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/FishGoddess/cryptox/ed25519"
)

var (
	ed25519BenchData = []byte("你好，世界")
)

// go test -v -bench=^BenchmarkED25519_Sign$ -benchtime=1s ed25519_test.go
func BenchmarkED25519_Sign(b *testing.B) {
	privateKey, err := ed25519.LoadPrivateKey("ed25519.key")
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		privateKey.Sign(ed25519BenchData)
	}
}

// go test -v -bench=^BenchmarkED25519_Verify$ -benchtime=1s ed25519_test.go
func BenchmarkED25519_Verify(b *testing.B) {
	privateKey, err := ed25519.LoadPrivateKey("ed25519.key")
	if err != nil {
		b.Fatal(err)
	}

	publicKey, err := ed25519.LoadPublicKey("ed25519.pub")
	if err != nil {
		b.Fatal(err)
	}

	sign := privateKey.Sign(ed25519BenchData)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err = publicKey.Verify(ed25519BenchData, sign)
		if err != nil {
			b.Fatal(err)
		}
	}
}
