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
	tripleDesBenchKey   = []byte("123456788765432112345678")
	tripleDesBenchIV    = []byte("87654321")
	tripleDesBenchPlain = make([]byte, 128)
)

// go test -v -bench=^BenchmarkTripleDESEncryptECB$ -benchtime=1s triple_des_test.go
func BenchmarkTripleDESEncryptECB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	desObj := des.NewTriple(tripleDesBenchKey)
	for i := 0; i < b.N; i++ {
		_, err := desObj.EncryptECB(cryptox.PaddingPKCS7, tripleDesBenchPlain)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkTripleDESEncryptCBC$ -benchtime=1s triple_des_test.go
func BenchmarkTripleDESEncryptCBC(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	desObj := des.NewTriple(tripleDesBenchKey)
	for i := 0; i < b.N; i++ {
		_, err := desObj.EncryptCBC(cryptox.PaddingPKCS7, tripleDesBenchIV, tripleDesBenchPlain)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkTripleDESEncryptCFB$ -benchtime=1s triple_des_test.go
func BenchmarkTripleDESEncryptCFB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	desObj := des.NewTriple(tripleDesBenchKey)
	for i := 0; i < b.N; i++ {
		_, err := desObj.EncryptCFB(cryptox.PaddingNone, tripleDesBenchIV, tripleDesBenchPlain)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkTripleDESEncryptOFB$ -benchtime=1s triple_des_test.go
func BenchmarkTripleDESEncryptOFB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	desObj := des.NewTriple(tripleDesBenchKey)
	for i := 0; i < b.N; i++ {
		_, err := desObj.EncryptOFB(cryptox.PaddingNone, tripleDesBenchIV, tripleDesBenchPlain)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkTripleDESEncryptCTR$ -benchtime=1s triple_des_test.go
func BenchmarkTripleDESEncryptCTR(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	desObj := des.NewTriple(tripleDesBenchKey)
	for i := 0; i < b.N; i++ {
		_, err := desObj.EncryptCTR(cryptox.PaddingNone, tripleDesBenchIV, tripleDesBenchPlain)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkTripleDESDecryptECB$ -benchtime=1s triple_des_test.go
func BenchmarkTripleDESDecryptECB(b *testing.B) {
	desObj := des.NewTriple(tripleDesBenchKey)

	benchCrypted, err := desObj.EncryptECB(cryptox.PaddingPKCS7, tripleDesBenchPlain)
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

// go test -v -bench=^BenchmarkTripleDESDecryptCBC$ -benchtime=1s triple_des_test.go
func BenchmarkTripleDESDecryptCBC(b *testing.B) {
	desObj := des.NewTriple(tripleDesBenchKey)

	benchCrypted, err := desObj.EncryptCBC(cryptox.PaddingPKCS7, tripleDesBenchIV, tripleDesBenchPlain)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := desObj.DecryptCBC(cryptox.UnPaddingPKCS7, tripleDesBenchIV, benchCrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkTripleDESDecryptCFB$ -benchtime=1s triple_des_test.go
func BenchmarkTripleDESDecryptCFB(b *testing.B) {
	desObj := des.NewTriple(tripleDesBenchKey)

	benchCrypted, err := desObj.EncryptCFB(cryptox.PaddingNone, tripleDesBenchIV, tripleDesBenchPlain)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := desObj.DecryptCFB(cryptox.UnPaddingNone, tripleDesBenchIV, benchCrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkTripleDESDecryptOFB$ -benchtime=1s triple_des_test.go
func BenchmarkTripleDESDecryptOFB(b *testing.B) {
	desObj := des.NewTriple(tripleDesBenchKey)

	benchCrypted, err := desObj.EncryptOFB(cryptox.PaddingNone, tripleDesBenchIV, tripleDesBenchPlain)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := desObj.DecryptOFB(cryptox.UnPaddingNone, tripleDesBenchIV, benchCrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkTripleDESDecryptCTR$ -benchtime=1s triple_des_test.go
func BenchmarkTripleDESDecryptCTR(b *testing.B) {
	desObj := des.NewTriple(tripleDesBenchKey)

	benchCrypted, err := desObj.EncryptCTR(cryptox.PaddingNone, tripleDesBenchIV, tripleDesBenchPlain)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := desObj.DecryptCTR(cryptox.UnPaddingNone, tripleDesBenchIV, benchCrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}
