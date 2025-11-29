// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/FishGoddess/cryptox/aes"
	"github.com/FishGoddess/cryptox/bytes/encoding"
	"github.com/FishGoddess/cryptox/bytes/padding"
)

var (
	aesBenchKey   = []byte("12345678876543211234567887654321")
	aesBenchIV    = []byte("8765432112345678")
	aesBenchNonce = []byte("123456abcdef")
	aesBenchMsg   = make([]byte, 128)
)

// go test -v -bench=^BenchmarkAES_EncryptECB$ -benchtime=1s des_test.go
func BenchmarkAES_EncryptECB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.EncryptECB(aesBenchMsg, aesBenchKey, padding.PKCS7, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAES_EncryptCBC$ -benchtime=1s des_test.go
func BenchmarkAES_EncryptCBC(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.EncryptCBC(aesBenchMsg, aesBenchKey, aesBenchIV, padding.PKCS7, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAES_EncryptCFB$ -benchtime=1s des_test.go
func BenchmarkAES_EncryptCFB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.EncryptCFB(aesBenchMsg, aesBenchKey, aesBenchIV, padding.None, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAES_EncryptOFB$ -benchtime=1s des_test.go
func BenchmarkAES_EncryptOFB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.EncryptOFB(aesBenchMsg, aesBenchKey, aesBenchIV, padding.None, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAES_EncryptCTR$ -benchtime=1s des_test.go
func BenchmarkAES_EncryptCTR(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.EncryptCTR(aesBenchMsg, aesBenchKey, aesBenchIV, padding.None, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESEncryptGCM$ -benchtime=1s aes_test.go
func BenchmarkAES_EncryptGCM(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.EncryptGCM(aesBenchMsg, aesBenchKey, aesBenchNonce, nil, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAES_DecryptECB$ -benchtime=1s des_test.go
func BenchmarkAES_DecryptECB(b *testing.B) {
	encrypted, err := aes.EncryptECB(aesBenchMsg, aesBenchKey, padding.PKCS7, encoding.None)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.DecryptECB(encrypted, aesBenchKey, padding.PKCS7, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAES_DecryptCBC$ -benchtime=1s des_test.go
func BenchmarkAES_DecryptCBC(b *testing.B) {
	encrypted, err := aes.EncryptCBC(aesBenchMsg, aesBenchKey, aesBenchIV, padding.PKCS7, encoding.None)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.DecryptCBC(encrypted, aesBenchKey, aesBenchIV, padding.PKCS7, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAES_DecryptCFB$ -benchtime=1s des_test.go
func BenchmarkAES_DecryptCFB(b *testing.B) {
	encrypted, err := aes.EncryptCFB(aesBenchMsg, aesBenchKey, aesBenchIV, padding.None, encoding.None)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.DecryptCFB(encrypted, aesBenchKey, aesBenchIV, padding.None, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAES_DecryptOFB$ -benchtime=1s des_test.go
func BenchmarkAES_DecryptOFB(b *testing.B) {
	encrypted, err := aes.EncryptOFB(aesBenchMsg, aesBenchKey, aesBenchIV, padding.None, encoding.None)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.DecryptOFB(encrypted, aesBenchKey, aesBenchIV, padding.None, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAES_DecryptCTR$ -benchtime=1s des_test.go
func BenchmarkAES_DecryptCTR(b *testing.B) {
	encrypted, err := aes.EncryptCTR(aesBenchMsg, aesBenchKey, aesBenchIV, padding.None, encoding.None)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.DecryptCTR(encrypted, aesBenchKey, aesBenchIV, padding.None, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESDecryptGCM$ -benchtime=1s aes_test.go
func BenchmarkAES_DecryptGCM(b *testing.B) {
	encrypted, err := aes.EncryptGCM(aesBenchMsg, aesBenchKey, aesBenchNonce, nil, encoding.None)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.DecryptGCM(encrypted, aesBenchKey, aesBenchNonce, nil, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}
