// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/FishGoddess/cryptox"
	"github.com/FishGoddess/cryptox/aes"
)

var (
	aesBenchKey   = []byte("12345678876543211234567887654321")
	aesBenchIV    = []byte("8765432112345678")
	aesBenchNonce = []byte("123456abcdef")
	aesBenchMsg   = cryptox.GenerateBytes(128)
)

// go test -v -bench=^BenchmarkAESEncryptECB$ -benchtime=1s aes_test.go
func BenchmarkAESEncryptECB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.EncryptECB(aesBenchKey, cryptox.PaddingPKCS7, aesBenchMsg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESEncryptCBC$ -benchtime=1s aes_test.go
func BenchmarkAESEncryptCBC(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.EncryptCBC(aesBenchKey, aesBenchIV, cryptox.PaddingPKCS7, aesBenchMsg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESEncryptCFB$ -benchtime=1s aes_test.go
func BenchmarkAESEncryptCFB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.EncryptCFB(aesBenchKey, aesBenchIV, cryptox.PaddingNone, aesBenchMsg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESEncryptOFB$ -benchtime=1s aes_test.go
func BenchmarkAESEncryptOFB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.EncryptOFB(aesBenchKey, aesBenchIV, cryptox.PaddingNone, aesBenchMsg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESEncryptCTR$ -benchtime=1s aes_test.go
func BenchmarkAESEncryptCTR(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.EncryptCTR(aesBenchKey, aesBenchIV, cryptox.PaddingNone, aesBenchMsg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESEncryptGCM$ -benchtime=1s aes_test.go
func BenchmarkAESEncryptGCM(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.EncryptGCM(aesBenchKey, aesBenchNonce, nil, aesBenchMsg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESDecryptECB$ -benchtime=1s aes_test.go
func BenchmarkAESDecryptECB(b *testing.B) {
	encrypted, err := aes.EncryptECB(aesBenchKey, cryptox.PaddingPKCS7, aesBenchMsg)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.DecryptECB(aesBenchKey, cryptox.PaddingPKCS7, encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESDecryptCBC$ -benchtime=1s aes_test.go
func BenchmarkAESDecryptCBC(b *testing.B) {
	encrypted, err := aes.EncryptCBC(aesBenchKey, aesBenchIV, cryptox.PaddingPKCS7, aesBenchMsg)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.DecryptCBC(aesBenchKey, aesBenchIV, cryptox.PaddingPKCS7, encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESDecryptCFB$ -benchtime=1s aes_test.go
func BenchmarkAESDecryptCFB(b *testing.B) {
	encrypted, err := aes.EncryptCFB(aesBenchKey, aesBenchIV, cryptox.PaddingNone, aesBenchMsg)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.DecryptCFB(aesBenchKey, aesBenchIV, cryptox.PaddingNone, encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESDecryptOFB$ -benchtime=1s aes_test.go
func BenchmarkAESDecryptOFB(b *testing.B) {
	encrypted, err := aes.EncryptOFB(aesBenchKey, aesBenchIV, cryptox.PaddingNone, aesBenchMsg)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.DecryptOFB(aesBenchKey, aesBenchIV, cryptox.PaddingNone, encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESDecryptCTR$ -benchtime=1s aes_test.go
func BenchmarkAESDecryptCTR(b *testing.B) {
	encrypted, err := aes.EncryptCTR(aesBenchKey, aesBenchIV, cryptox.PaddingNone, aesBenchMsg)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.DecryptCTR(aesBenchKey, aesBenchIV, cryptox.PaddingNone, encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESDecryptGCM$ -benchtime=1s aes_test.go
func BenchmarkAESDecryptGCM(b *testing.B) {
	encrypted, err := aes.EncryptGCM(aesBenchKey, aesBenchNonce, nil, aesBenchMsg)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.DecryptGCM(aesBenchKey, aesBenchNonce, nil, encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}
