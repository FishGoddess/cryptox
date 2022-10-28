// Copyright 2022 FishGoddess. All rights reserved.
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
	aesBenchPlain = make([]byte, 128)
)

// go test -v -bench=^BenchmarkAESEncryptWithECB$ -benchtime=1s aes_test.go
func BenchmarkAESEncryptWithECB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.ECBEncrypter(aesBenchKey, cryptox.PaddingPKCS7).Encrypt(aesBenchPlain)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESEncryptWithCBC$ -benchtime=1s aes_test.go
func BenchmarkAESEncryptWithCBC(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.CBCEncrypter(aesBenchKey, aesBenchIV, cryptox.PaddingPKCS7).Encrypt(aesBenchPlain)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESEncryptWithCFB$ -benchtime=1s aes_test.go
func BenchmarkAESEncryptWithCFB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.CFBEncrypter(aesBenchKey, aesBenchIV, cryptox.PaddingNone).Encrypt(aesBenchPlain)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESEncryptWithOFB$ -benchtime=1s aes_test.go
func BenchmarkAESEncryptWithOFB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.OFBEncrypter(aesBenchKey, aesBenchIV, cryptox.PaddingNone).Encrypt(aesBenchPlain)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESEncryptWithCTR$ -benchtime=1s aes_test.go
func BenchmarkAESEncryptWithCTR(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.CTREncrypter(aesBenchKey, aesBenchIV, cryptox.PaddingNone).Encrypt(aesBenchPlain)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESDecryptWithECB$ -benchtime=1s aes_test.go
func BenchmarkAESDecryptWithECB(b *testing.B) {
	benchCrypted, err := aes.ECBEncrypter(aesBenchKey, cryptox.PaddingPKCS7).Encrypt(aesBenchPlain)
	if err != nil {
		b.Error(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.ECBDecrypter(aesBenchKey, cryptox.UnPaddingPKCS7).Decrypt(benchCrypted)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESDecryptWithCBC$ -benchtime=1s aes_test.go
func BenchmarkAESDecryptWithCBC(b *testing.B) {
	benchCrypted, err := aes.CBCEncrypter(aesBenchKey, aesBenchIV, cryptox.PaddingPKCS7).Encrypt(aesBenchPlain)
	if err != nil {
		b.Error(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.CBCDecrypter(aesBenchKey, aesBenchIV, cryptox.UnPaddingPKCS7).Decrypt(benchCrypted)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESDecryptWithCFB$ -benchtime=1s aes_test.go
func BenchmarkAESDecryptWithCFB(b *testing.B) {
	benchCrypted, err := aes.CFBEncrypter(aesBenchKey, aesBenchIV, cryptox.PaddingNone).Encrypt(aesBenchPlain)
	if err != nil {
		b.Error(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.CFBDecrypter(aesBenchKey, aesBenchIV, cryptox.UnPaddingNone).Decrypt(benchCrypted)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESDecryptWithOFB$ -benchtime=1s aes_test.go
func BenchmarkAESDecryptWithOFB(b *testing.B) {
	benchCrypted, err := aes.OFBEncrypter(aesBenchKey, aesBenchIV, cryptox.PaddingNone).Encrypt(aesBenchPlain)
	if err != nil {
		b.Error(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.OFBDecrypter(aesBenchKey, aesBenchIV, cryptox.UnPaddingNone).Decrypt(benchCrypted)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkAESDecryptWithCTR$ -benchtime=1s aes_test.go
func BenchmarkAESDecryptWithCTR(b *testing.B) {
	benchCrypted, err := aes.CTREncrypter(aesBenchKey, aesBenchIV, cryptox.PaddingNone).Encrypt(aesBenchPlain)
	if err != nil {
		b.Error(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aes.CTRDecrypter(aesBenchKey, aesBenchIV, cryptox.UnPaddingNone).Decrypt(benchCrypted)
		if err != nil {
			b.Error(err)
		}
	}
}
