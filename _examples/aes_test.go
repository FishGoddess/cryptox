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
	aesBenchKey      = []byte("12345678876543211234567887654321")
	aesBenchIV       = []byte("8765432112345678")
	aesBenchNonce    = []byte("123456abcdef")
	aesBenchPlain, _ = cryptox.GenerateBytes(128)
)

// go test -v -bench=^BenchmarkAESEncryptECB$ -benchtime=1s aes_test.go
func BenchmarkAESEncryptECB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	aesObj := aes.New(aesBenchKey)
	for i := 0; i < b.N; i++ {
		_, err := aesObj.EncryptECB(cryptox.PaddingPKCS7, aesBenchPlain)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESEncryptCBC$ -benchtime=1s aes_test.go
func BenchmarkAESEncryptCBC(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	aesObj := aes.New(aesBenchKey)
	for i := 0; i < b.N; i++ {
		_, err := aesObj.EncryptCBC(cryptox.PaddingPKCS7, aesBenchIV, aesBenchPlain)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESEncryptCFB$ -benchtime=1s aes_test.go
func BenchmarkAESEncryptCFB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	aesObj := aes.New(aesBenchKey)
	for i := 0; i < b.N; i++ {
		_, err := aesObj.EncryptCFB(cryptox.PaddingNone, aesBenchIV, aesBenchPlain)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESEncryptOFB$ -benchtime=1s aes_test.go
func BenchmarkAESEncryptOFB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	aesObj := aes.New(aesBenchKey)
	for i := 0; i < b.N; i++ {
		_, err := aesObj.EncryptOFB(cryptox.PaddingNone, aesBenchIV, aesBenchPlain)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESEncryptCTR$ -benchtime=1s aes_test.go
func BenchmarkAESEncryptCTR(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	aesObj := aes.New(aesBenchKey)
	for i := 0; i < b.N; i++ {
		_, err := aesObj.EncryptCTR(cryptox.PaddingNone, aesBenchIV, aesBenchPlain)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESEncryptGCM$ -benchtime=1s aes_test.go
func BenchmarkAESEncryptGCM(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	aesObj := aes.New(aesBenchKey)
	for i := 0; i < b.N; i++ {
		_, err := aesObj.EncryptGCM(aesBenchNonce, aesBenchPlain, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESDecryptECB$ -benchtime=1s aes_test.go
func BenchmarkAESDecryptECB(b *testing.B) {
	aesObj := aes.New(aesBenchKey)

	benchCrypted, err := aesObj.EncryptECB(cryptox.PaddingPKCS7, aesBenchPlain)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aesObj.DecryptECB(cryptox.UnPaddingPKCS7, benchCrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESDecryptCBC$ -benchtime=1s aes_test.go
func BenchmarkAESDecryptCBC(b *testing.B) {
	aesObj := aes.New(aesBenchKey)

	benchCrypted, err := aesObj.EncryptCBC(cryptox.PaddingPKCS7, aesBenchIV, aesBenchPlain)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aesObj.DecryptCBC(cryptox.UnPaddingPKCS7, aesBenchIV, benchCrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESDecryptCFB$ -benchtime=1s aes_test.go
func BenchmarkAESDecryptCFB(b *testing.B) {
	aesObj := aes.New(aesBenchKey)

	benchCrypted, err := aesObj.EncryptCFB(cryptox.PaddingNone, aesBenchIV, aesBenchPlain)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aesObj.DecryptCFB(cryptox.UnPaddingNone, aesBenchIV, benchCrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESDecryptOFB$ -benchtime=1s aes_test.go
func BenchmarkAESDecryptOFB(b *testing.B) {
	aesObj := aes.New(aesBenchKey)

	benchCrypted, err := aesObj.EncryptOFB(cryptox.PaddingNone, aesBenchIV, aesBenchPlain)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aesObj.DecryptOFB(cryptox.UnPaddingNone, aesBenchIV, benchCrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESDecryptCTR$ -benchtime=1s aes_test.go
func BenchmarkAESDecryptCTR(b *testing.B) {
	aesObj := aes.New(aesBenchKey)

	benchCrypted, err := aesObj.EncryptCTR(cryptox.PaddingNone, aesBenchIV, aesBenchPlain)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aesObj.DecryptCTR(cryptox.UnPaddingNone, aesBenchIV, benchCrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESDecryptGCM$ -benchtime=1s aes_test.go
func BenchmarkAESDecryptGCM(b *testing.B) {
	aesObj := aes.New(aesBenchKey)

	benchCrypted, err := aesObj.EncryptGCM(aesBenchNonce, aesBenchPlain, nil)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aesObj.DecryptGCM(aesBenchNonce, benchCrypted, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}
