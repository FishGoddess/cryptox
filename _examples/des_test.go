// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"testing"

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
		_, err := des.EncryptECB(desBenchMsg, desBenchKey, des.WithPKCS7())
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
		_, err := des.EncryptCBC(desBenchMsg, desBenchKey, desBenchIV, des.WithPKCS7())
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
		_, err := des.EncryptCFB(desBenchMsg, desBenchKey, desBenchIV)
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
		_, err := des.EncryptOFB(desBenchMsg, desBenchKey, desBenchIV)
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
		_, err := des.EncryptCTR(desBenchMsg, desBenchKey, desBenchIV)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDES_DecryptECB$ -benchtime=1s des_test.go
func BenchmarkDES_DecryptECB(b *testing.B) {
	encrypt, err := des.EncryptECB(desBenchMsg, desBenchKey, des.WithPKCS7())
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.DecryptECB(encrypt, desBenchKey, des.WithPKCS7())
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDES_DecryptCBC$ -benchtime=1s des_test.go
func BenchmarkDES_DecryptCBC(b *testing.B) {
	encrypt, err := des.EncryptCBC(desBenchMsg, desBenchKey, desBenchIV, des.WithPKCS7())
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.DecryptCBC(encrypt, desBenchKey, desBenchIV, des.WithPKCS7())
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDES_DecryptCFB$ -benchtime=1s des_test.go
func BenchmarkDES_DecryptCFB(b *testing.B) {
	encrypt, err := des.EncryptCFB(desBenchMsg, desBenchKey, desBenchIV)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.DecryptCFB(encrypt, desBenchKey, desBenchIV)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDES_DecryptOFB$ -benchtime=1s des_test.go
func BenchmarkDES_DecryptOFB(b *testing.B) {
	encrypt, err := des.EncryptOFB(desBenchMsg, desBenchKey, desBenchIV)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.DecryptOFB(encrypt, desBenchKey, desBenchIV)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDES_DecryptCTR$ -benchtime=1s des_test.go
func BenchmarkDES_DecryptCTR(b *testing.B) {
	encrypt, err := des.EncryptCTR(desBenchMsg, desBenchKey, desBenchIV)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.DecryptCTR(encrypt, desBenchKey, desBenchIV)
		if err != nil {
			b.Fatal(err)
		}
	}
}
