// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/FishGoddess/cryptox/bytes/encoding"
	"github.com/FishGoddess/cryptox/bytes/padding"
	"github.com/FishGoddess/cryptox/des"
)

var (
	desBenchKey = []byte("12345678")
	desBenchIV  = []byte("87654321")
	desBenchMsg = make([]byte, 128)
)

// go test -v -bench=^BenchmarkDES_EncryptECB$ -benchtime=1s des_test.go
func BenchmarkDES_EncryptECB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.EncryptECB(desBenchMsg, desBenchKey, padding.PKCS7, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDES_EncryptCBC$ -benchtime=1s des_test.go
func BenchmarkDES_EncryptCBC(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.EncryptCBC(desBenchMsg, desBenchKey, desBenchIV, padding.PKCS7, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDES_EncryptCFB$ -benchtime=1s des_test.go
func BenchmarkDES_EncryptCFB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.EncryptCFB(desBenchMsg, desBenchKey, desBenchIV, padding.None, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDES_EncryptOFB$ -benchtime=1s des_test.go
func BenchmarkDES_EncryptOFB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.EncryptOFB(desBenchMsg, desBenchKey, desBenchIV, padding.None, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDES_EncryptCTR$ -benchtime=1s des_test.go
func BenchmarkDES_EncryptCTR(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.EncryptCTR(desBenchMsg, desBenchKey, desBenchIV, padding.None, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDES_DecryptECB$ -benchtime=1s des_test.go
func BenchmarkDES_DecryptECB(b *testing.B) {
	encrypted, err := des.EncryptECB(desBenchMsg, desBenchKey, padding.PKCS7, encoding.None)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.DecryptECB(encrypted, desBenchKey, padding.PKCS7, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDES_DecryptCBC$ -benchtime=1s des_test.go
func BenchmarkDES_DecryptCBC(b *testing.B) {
	encrypted, err := des.EncryptCBC(desBenchMsg, desBenchKey, desBenchIV, padding.PKCS7, encoding.None)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.DecryptCBC(encrypted, desBenchKey, desBenchIV, padding.PKCS7, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDES_DecryptCFB$ -benchtime=1s des_test.go
func BenchmarkDES_DecryptCFB(b *testing.B) {
	encrypted, err := des.EncryptCFB(desBenchMsg, desBenchKey, desBenchIV, padding.None, encoding.None)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.DecryptCFB(encrypted, desBenchKey, desBenchIV, padding.None, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDES_DecryptOFB$ -benchtime=1s des_test.go
func BenchmarkDES_DecryptOFB(b *testing.B) {
	encrypted, err := des.EncryptOFB(desBenchMsg, desBenchKey, desBenchIV, padding.None, encoding.None)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.DecryptOFB(encrypted, desBenchKey, desBenchIV, padding.None, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDES_DecryptCTR$ -benchtime=1s des_test.go
func BenchmarkDES_DecryptCTR(b *testing.B) {
	encrypted, err := des.EncryptCTR(desBenchMsg, desBenchKey, desBenchIV, padding.None, encoding.None)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.DecryptCTR(encrypted, desBenchKey, desBenchIV, padding.None, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}
