// Copyright 2023 FishGoddess. All rights reserved.
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

// go test -v -bench=^BenchmarkTripleDESEncryptWithECB$ -benchtime=1s triple_des_test.go
func BenchmarkTripleDESEncryptWithECB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.TripleECBEncrypter(tripleDesBenchKey, cryptox.PaddingPKCS7).Encrypt(tripleDesBenchPlain)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkTripleDESEncryptWithCBC$ -benchtime=1s triple_des_test.go
func BenchmarkTripleDESEncryptWithCBC(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.TripleCBCEncrypter(tripleDesBenchKey, tripleDesBenchIV, cryptox.PaddingPKCS7).Encrypt(tripleDesBenchPlain)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkTripleDESEncryptWithCFB$ -benchtime=1s triple_des_test.go
func BenchmarkTripleDESEncryptWithCFB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.TripleCFBEncrypter(tripleDesBenchKey, tripleDesBenchIV, cryptox.PaddingNone).Encrypt(tripleDesBenchPlain)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkTripleDESEncryptWithOFB$ -benchtime=1s triple_des_test.go
func BenchmarkTripleDESEncryptWithOFB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.TripleOFBEncrypter(tripleDesBenchKey, tripleDesBenchIV, cryptox.PaddingNone).Encrypt(tripleDesBenchPlain)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkTripleDESEncryptWithCTR$ -benchtime=1s triple_des_test.go
func BenchmarkTripleDESEncryptWithCTR(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.TripleCTREncrypter(tripleDesBenchKey, tripleDesBenchIV, cryptox.PaddingNone).Encrypt(tripleDesBenchPlain)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkTripleDESDecryptWithECB$ -benchtime=1s triple_des_test.go
func BenchmarkTripleDESDecryptWithECB(b *testing.B) {
	benchCrypted, err := des.TripleECBEncrypter(tripleDesBenchKey, cryptox.PaddingPKCS7).Encrypt(tripleDesBenchPlain)
	if err != nil {
		b.Error(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.TripleECBDecrypter(tripleDesBenchKey, cryptox.UnPaddingPKCS7).Decrypt(benchCrypted)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkTripleDESDecryptWithCBC$ -benchtime=1s triple_des_test.go
func BenchmarkTripleDESDecryptWithCBC(b *testing.B) {
	benchCrypted, err := des.TripleCBCEncrypter(tripleDesBenchKey, tripleDesBenchIV, cryptox.PaddingPKCS7).Encrypt(tripleDesBenchPlain)
	if err != nil {
		b.Error(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.TripleCBCDecrypter(tripleDesBenchKey, tripleDesBenchIV, cryptox.UnPaddingPKCS7).Decrypt(benchCrypted)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkTripleDESDecryptWithCFB$ -benchtime=1s triple_des_test.go
func BenchmarkTripleDESDecryptWithCFB(b *testing.B) {
	benchCrypted, err := des.TripleCFBEncrypter(tripleDesBenchKey, tripleDesBenchIV, cryptox.PaddingNone).Encrypt(tripleDesBenchPlain)
	if err != nil {
		b.Error(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.TripleCFBDecrypter(tripleDesBenchKey, tripleDesBenchIV, cryptox.UnPaddingNone).Decrypt(benchCrypted)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkTripleDESDecryptWithOFB$ -benchtime=1s triple_des_test.go
func BenchmarkTripleDESDecryptWithOFB(b *testing.B) {
	benchCrypted, err := des.TripleOFBEncrypter(tripleDesBenchKey, tripleDesBenchIV, cryptox.PaddingNone).Encrypt(tripleDesBenchPlain)
	if err != nil {
		b.Error(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.TripleOFBDecrypter(tripleDesBenchKey, tripleDesBenchIV, cryptox.UnPaddingNone).Decrypt(benchCrypted)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkTripleDESDecryptWithCTR$ -benchtime=1s triple_des_test.go
func BenchmarkTripleDESDecryptWithCTR(b *testing.B) {
	benchCrypted, err := des.TripleCTREncrypter(tripleDesBenchKey, tripleDesBenchIV, cryptox.PaddingNone).Encrypt(tripleDesBenchPlain)
	if err != nil {
		b.Error(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.TripleCTRDecrypter(tripleDesBenchKey, tripleDesBenchIV, cryptox.UnPaddingNone).Decrypt(benchCrypted)
		if err != nil {
			b.Error(err)
		}
	}
}
