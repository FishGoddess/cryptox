// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/FishGoddess/cryptox"
	"github.com/FishGoddess/cryptox/des"
)

var (
	tripleDesBenchKey = []byte("123456788765432112345678")
	tripleDesBenchIV  = []byte("87654321")
	tripleDesBenchMsg = make([]byte, 128)
)

// go test -v -bench=^BenchmarkDESEncryptECBTriple$ -benchtime=1s triple_des_test.go
func BenchmarkDESEncryptECBTriple(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.EncryptECBTriple(tripleDesBenchKey, cryptox.PaddingPKCS7, tripleDesBenchMsg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESEncryptCBCTriple$ -benchtime=1s triple_des_test.go
func BenchmarkDESEncryptCBCTriple(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.EncryptCBCTriple(tripleDesBenchKey, tripleDesBenchIV, cryptox.PaddingPKCS7, tripleDesBenchMsg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESEncryptCFBTriple$ -benchtime=1s triple_des_test.go
func BenchmarkDESEncryptCFBTriple(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.EncryptCFBTriple(tripleDesBenchKey, tripleDesBenchIV, cryptox.PaddingNone, tripleDesBenchMsg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESEncryptOFBTriple$ -benchtime=1s triple_des_test.go
func BenchmarkDESEncryptOFBTriple(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.EncryptOFBTriple(tripleDesBenchKey, tripleDesBenchIV, cryptox.PaddingNone, tripleDesBenchMsg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESEncryptCTRTriple$ -benchtime=1s triple_des_test.go
func BenchmarkDESEncryptCTRTriple(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.EncryptCTRTriple(tripleDesBenchKey, tripleDesBenchIV, cryptox.PaddingNone, tripleDesBenchMsg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESDecryptECBTriple$ -benchtime=1s triple_des_test.go
func BenchmarkDESDecryptECBTriple(b *testing.B) {
	encrypted, err := des.EncryptECBTriple(tripleDesBenchKey, cryptox.PaddingPKCS7, tripleDesBenchMsg)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.DecryptECBTriple(tripleDesBenchKey, cryptox.PaddingPKCS7, encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESDecryptCBCTriple$ -benchtime=1s triple_des_test.go
func BenchmarkDESDecryptCBCTriple(b *testing.B) {
	encrypted, err := des.EncryptCBCTriple(tripleDesBenchKey, tripleDesBenchIV, cryptox.PaddingPKCS7, tripleDesBenchMsg)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.DecryptCBCTriple(tripleDesBenchKey, tripleDesBenchIV, cryptox.PaddingPKCS7, encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESDecryptCFBTriple$ -benchtime=1s triple_des_test.go
func BenchmarkDESDecryptCFBTriple(b *testing.B) {
	encrypted, err := des.EncryptCFBTriple(tripleDesBenchKey, tripleDesBenchIV, cryptox.PaddingNone, tripleDesBenchMsg)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.DecryptCFBTriple(tripleDesBenchKey, tripleDesBenchIV, cryptox.PaddingNone, encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESDecryptOFBTriple$ -benchtime=1s triple_des_test.go
func BenchmarkDESDecryptOFBTriple(b *testing.B) {
	encrypted, err := des.EncryptOFBTriple(tripleDesBenchKey, tripleDesBenchIV, cryptox.PaddingNone, tripleDesBenchMsg)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.DecryptOFBTriple(tripleDesBenchKey, tripleDesBenchIV, cryptox.PaddingNone, encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESDecryptCTRTriple$ -benchtime=1s triple_des_test.go
func BenchmarkDESDecryptCTRTriple(b *testing.B) {
	encrypted, err := des.EncryptCTRTriple(tripleDesBenchKey, tripleDesBenchIV, cryptox.PaddingNone, tripleDesBenchMsg)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.DecryptCTRTriple(tripleDesBenchKey, tripleDesBenchIV, cryptox.PaddingNone, encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}
