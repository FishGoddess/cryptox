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
	desBenchKey   = []byte("12345678")
	desBenchIV    = []byte("87654321")
	desBenchPlain = make([]byte, 128)
)

// go test -v -bench=^BenchmarkDESEncryptECB$ -benchtime=1s des_test.go
func BenchmarkDESEncryptECB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	desObj := des.New(desBenchKey)
	for i := 0; i < b.N; i++ {
		_, err := desObj.EncryptECB(cryptox.PaddingPKCS7, desBenchPlain)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESEncryptCBC$ -benchtime=1s des_test.go
func BenchmarkDESEncryptCBC(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	desObj := des.New(desBenchKey)
	for i := 0; i < b.N; i++ {
		_, err := desObj.EncryptCBC(cryptox.PaddingPKCS7, desBenchIV, desBenchPlain)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESEncryptCFB$ -benchtime=1s des_test.go
func BenchmarkDESEncryptCFB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	desObj := des.New(desBenchKey)
	for i := 0; i < b.N; i++ {
		_, err := desObj.EncryptCFB(cryptox.PaddingPKCS7, desBenchIV, desBenchPlain)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESEncryptOFB$ -benchtime=1s des_test.go
func BenchmarkDESEncryptOFB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	desObj := des.New(desBenchKey)
	for i := 0; i < b.N; i++ {
		_, err := desObj.EncryptOFB(cryptox.PaddingPKCS7, desBenchIV, desBenchPlain)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESEncryptCTR$ -benchtime=1s des_test.go
func BenchmarkDESEncryptCTR(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	desObj := des.New(desBenchKey)
	for i := 0; i < b.N; i++ {
		_, err := desObj.EncryptCTR(cryptox.PaddingPKCS7, desBenchIV, desBenchPlain)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESDecryptECB$ -benchtime=1s des_test.go
func BenchmarkDESDecryptECB(b *testing.B) {
	desObj := des.New(desBenchKey)

	benchCrypted, err := desObj.EncryptECB(cryptox.PaddingPKCS7, desBenchPlain)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := desObj.DecryptECB(cryptox.UnPaddingPKCS7, benchCrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESDecryptCBC$ -benchtime=1s des_test.go
func BenchmarkDESDecryptCBC(b *testing.B) {
	desObj := des.New(desBenchKey)

	benchCrypted, err := desObj.EncryptCBC(cryptox.PaddingPKCS7, desBenchIV, desBenchPlain)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := desObj.DecryptCBC(cryptox.UnPaddingPKCS7, desBenchIV, benchCrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESDecryptCFB$ -benchtime=1s des_test.go
func BenchmarkDESDecryptCFB(b *testing.B) {
	desObj := des.New(desBenchKey)

	benchCrypted, err := desObj.EncryptCFB(cryptox.PaddingNone, desBenchIV, desBenchPlain)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := desObj.DecryptCFB(cryptox.UnPaddingNone, desBenchIV, benchCrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESDecryptOFB$ -benchtime=1s des_test.go
func BenchmarkDESDecryptOFB(b *testing.B) {
	desObj := des.New(desBenchKey)

	benchCrypted, err := desObj.EncryptOFB(cryptox.PaddingNone, desBenchIV, desBenchPlain)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := desObj.DecryptOFB(cryptox.UnPaddingNone, desBenchIV, benchCrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESDecryptCTR$ -benchtime=1s des_test.go
func BenchmarkDESDecryptCTR(b *testing.B) {
	desObj := des.New(desBenchKey)

	benchCrypted, err := desObj.EncryptCTR(cryptox.PaddingNone, desBenchIV, desBenchPlain)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := desObj.DecryptCTR(cryptox.UnPaddingNone, desBenchIV, benchCrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}
