// Copyright 2022 FishGoddess. All rights reserved.
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

// go test -v -bench=^BenchmarkDESEncryptWithECB$ -benchtime=1s des_test.go
func BenchmarkDESEncryptWithECB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.ECBEncrypter(desBenchKey, cryptox.PaddingPKCS7).Encrypt(desBenchPlain)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESEncryptWithCBC$ -benchtime=1s des_test.go
func BenchmarkDESEncryptWithCBC(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.CBCEncrypter(desBenchKey, desBenchIV, cryptox.PaddingPKCS7).Encrypt(desBenchPlain)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESEncryptWithCFB$ -benchtime=1s des_test.go
func BenchmarkDESEncryptWithCFB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.CFBEncrypter(desBenchKey, desBenchIV, cryptox.PaddingNone).Encrypt(desBenchPlain)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESEncryptWithOFB$ -benchtime=1s des_test.go
func BenchmarkDESEncryptWithOFB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.OFBEncrypter(desBenchKey, desBenchIV, cryptox.PaddingNone).Encrypt(desBenchPlain)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESEncryptWithCTR$ -benchtime=1s des_test.go
func BenchmarkDESEncryptWithCTR(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.CTREncrypter(desBenchKey, desBenchIV, cryptox.PaddingNone).Encrypt(desBenchPlain)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESDecryptWithECB$ -benchtime=1s des_test.go
func BenchmarkDESDecryptWithECB(b *testing.B) {
	benchCrypted, err := des.ECBEncrypter(desBenchKey, cryptox.PaddingPKCS7).Encrypt(desBenchPlain)
	if err != nil {
		b.Error(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.ECBDecrypter(desBenchKey, cryptox.UnPaddingPKCS7).Decrypt(benchCrypted)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESDecryptWithCBC$ -benchtime=1s des_test.go
func BenchmarkDESDecryptWithCBC(b *testing.B) {
	benchCrypted, err := des.CBCEncrypter(desBenchKey, desBenchIV, cryptox.PaddingPKCS7).Encrypt(desBenchPlain)
	if err != nil {
		b.Error(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.CBCDecrypter(desBenchKey, desBenchIV, cryptox.UnPaddingPKCS7).Decrypt(benchCrypted)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESDecryptWithCFB$ -benchtime=1s des_test.go
func BenchmarkDESDecryptWithCFB(b *testing.B) {
	benchCrypted, err := des.CFBEncrypter(desBenchKey, desBenchIV, cryptox.PaddingNone).Encrypt(desBenchPlain)
	if err != nil {
		b.Error(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.CFBDecrypter(desBenchKey, desBenchIV, cryptox.UnPaddingNone).Decrypt(benchCrypted)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESDecryptWithOFB$ -benchtime=1s des_test.go
func BenchmarkDESDecryptWithOFB(b *testing.B) {
	benchCrypted, err := des.OFBEncrypter(desBenchKey, desBenchIV, cryptox.PaddingNone).Encrypt(desBenchPlain)
	if err != nil {
		b.Error(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.OFBDecrypter(desBenchKey, desBenchIV, cryptox.UnPaddingNone).Decrypt(benchCrypted)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkDESDecryptWithCTR$ -benchtime=1s des_test.go
func BenchmarkDESDecryptWithCTR(b *testing.B) {
	benchCrypted, err := des.CTREncrypter(desBenchKey, desBenchIV, cryptox.PaddingNone).Encrypt(desBenchPlain)
	if err != nil {
		b.Error(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.CTRDecrypter(desBenchKey, desBenchIV, cryptox.UnPaddingNone).Decrypt(benchCrypted)
		if err != nil {
			b.Error(err)
		}
	}
}
