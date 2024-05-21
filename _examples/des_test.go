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
	desBenchKey = []byte("12345678")
	desBenchIV  = []byte("87654321")
	desBenchMsg = make([]byte, 128)
)

// go test -v -bench=^BenchmarkDESEncryptECB$ -benchtime=1s des_test.go
func BenchmarkDESEncryptECB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.EncryptECB(desBenchKey, cryptox.PaddingPKCS7, desBenchMsg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESEncryptCBC$ -benchtime=1s des_test.go
func BenchmarkDESEncryptCBC(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.EncryptCBC(desBenchKey, desBenchIV, cryptox.PaddingPKCS7, desBenchMsg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESEncryptCFB$ -benchtime=1s des_test.go
func BenchmarkDESEncryptCFB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.EncryptCFB(desBenchKey, desBenchIV, cryptox.PaddingNone, desBenchMsg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESEncryptOFB$ -benchtime=1s des_test.go
func BenchmarkDESEncryptOFB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.EncryptOFB(desBenchKey, desBenchIV, cryptox.PaddingNone, desBenchMsg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESEncryptCTR$ -benchtime=1s des_test.go
func BenchmarkDESEncryptCTR(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.EncryptCTR(desBenchKey, desBenchIV, cryptox.PaddingNone, desBenchMsg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESDecryptECB$ -benchtime=1s des_test.go
func BenchmarkDESDecryptECB(b *testing.B) {
	encrypted, err := des.EncryptECB(desBenchKey, cryptox.PaddingPKCS7, desBenchMsg)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.DecryptECB(desBenchKey, cryptox.PaddingPKCS7, encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESDecryptCBC$ -benchtime=1s des_test.go
func BenchmarkDESDecryptCBC(b *testing.B) {
	encrypted, err := des.EncryptCBC(desBenchKey, desBenchIV, cryptox.PaddingPKCS7, desBenchMsg)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.DecryptCBC(desBenchKey, desBenchIV, cryptox.PaddingPKCS7, encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESDecryptCFB$ -benchtime=1s des_test.go
func BenchmarkDESDecryptCFB(b *testing.B) {
	encrypted, err := des.EncryptCFB(desBenchKey, desBenchIV, cryptox.PaddingNone, desBenchMsg)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.DecryptCFB(desBenchKey, desBenchIV, cryptox.PaddingNone, encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESDecryptOFB$ -benchtime=1s des_test.go
func BenchmarkDESDecryptOFB(b *testing.B) {
	encrypted, err := des.EncryptOFB(desBenchKey, desBenchIV, cryptox.PaddingNone, desBenchMsg)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.DecryptOFB(desBenchKey, desBenchIV, cryptox.PaddingNone, encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESDecryptCTR$ -benchtime=1s des_test.go
func BenchmarkDESDecryptCTR(b *testing.B) {
	encrypted, err := des.EncryptCTR(desBenchKey, desBenchIV, cryptox.PaddingNone, desBenchMsg)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.DecryptCTR(desBenchKey, desBenchIV, cryptox.PaddingNone, encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}
