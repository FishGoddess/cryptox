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
	tripleDesBenchKey = []byte("123456788765432112345678")
	tripleDesBenchIV  = []byte("87654321")
	tripleDesBenchMsg = make([]byte, 128)
)

// go test -v -bench=^BenchmarkDES_EncryptTripleECB$ -benchtime=1s des_test.go
func BenchmarkDES_EncryptTripleECB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.EncryptTripleECB(tripleDesBenchMsg, tripleDesBenchKey, padding.PKCS7, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDES_EncryptTripleCBC$ -benchtime=1s des_test.go
func BenchmarkDES_EncryptTripleCBC(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.EncryptTripleCBC(tripleDesBenchMsg, tripleDesBenchKey, tripleDesBenchIV, padding.PKCS7, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDES_EncryptTripleCFB$ -benchtime=1s des_test.go
func BenchmarkDES_EncryptTripleCFB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.EncryptTripleCFB(tripleDesBenchMsg, tripleDesBenchKey, tripleDesBenchIV, padding.None, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDES_EncryptTripleOFB$ -benchtime=1s des_test.go
func BenchmarkDES_EncryptTripleOFB(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.EncryptTripleOFB(tripleDesBenchMsg, tripleDesBenchKey, tripleDesBenchIV, padding.None, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDES_EncryptTripleCTR$ -benchtime=1s des_test.go
func BenchmarkDES_EncryptTripleCTR(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.EncryptTripleCTR(tripleDesBenchMsg, tripleDesBenchKey, tripleDesBenchIV, padding.None, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDES_DecryptTripleECB$ -benchtime=1s des_test.go
func BenchmarkDES_DecryptTripleECB(b *testing.B) {
	encrypt, err := des.EncryptTripleECB(tripleDesBenchMsg, tripleDesBenchKey, padding.PKCS7, encoding.None)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.DecryptTripleECB(encrypt, tripleDesBenchKey, padding.PKCS7, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDES_DecryptTripleCBC$ -benchtime=1s des_test.go
func BenchmarkDES_DecryptTripleCBC(b *testing.B) {
	encrypt, err := des.EncryptTripleCBC(tripleDesBenchMsg, tripleDesBenchKey, tripleDesBenchIV, padding.PKCS7, encoding.None)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.DecryptTripleCBC(encrypt, tripleDesBenchKey, tripleDesBenchIV, padding.PKCS7, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDES_DecryptTripleCFB$ -benchtime=1s des_test.go
func BenchmarkDES_DecryptTripleCFB(b *testing.B) {
	encrypt, err := des.EncryptTripleCFB(tripleDesBenchMsg, tripleDesBenchKey, tripleDesBenchIV, padding.None, encoding.None)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.DecryptTripleCFB(encrypt, tripleDesBenchKey, tripleDesBenchIV, padding.None, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDES_DecryptTripleOFB$ -benchtime=1s des_test.go
func BenchmarkDES_DecryptTripleOFB(b *testing.B) {
	encrypt, err := des.EncryptTripleOFB(tripleDesBenchMsg, tripleDesBenchKey, tripleDesBenchIV, padding.None, encoding.None)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.DecryptTripleOFB(encrypt, tripleDesBenchKey, tripleDesBenchIV, padding.None, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkDES_DecryptTripleCTR$ -benchtime=1s des_test.go
func BenchmarkDES_DecryptTripleCTR(b *testing.B) {
	encrypt, err := des.EncryptTripleCTR(tripleDesBenchMsg, tripleDesBenchKey, tripleDesBenchIV, padding.None, encoding.None)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := des.DecryptTripleCTR(encrypt, tripleDesBenchKey, tripleDesBenchIV, padding.None, encoding.None)
		if err != nil {
			b.Fatal(err)
		}
	}
}
