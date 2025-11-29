// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/FishGoddess/cryptox/bytes/encoding"
	"github.com/FishGoddess/cryptox/hmac"
)

var (
	hmacBenchKey  = []byte("key")
	hmacBenchData = []byte("你好，世界")
)

// go test -v -bench=^BenchmarkHMAC_MD5$ -benchtime=1s hash_test.go
func BenchmarkHMAC_MD5(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hmac.MD5(hmacBenchData, hmacBenchKey, encoding.None)
	}
}

// go test -v -bench=^BenchmarkHMAC_SHA1$ -benchtime=1s hash_test.go
func BenchmarkHMAC_SHA1(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hmac.SHA1(hmacBenchData, hmacBenchKey, encoding.None)
	}
}

// go test -v -bench=^BenchmarkHMAC_SHA224$ -benchtime=1s hash_test.go
func BenchmarkHMAC_SHA224(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hmac.SHA224(hmacBenchData, hmacBenchKey, encoding.None)
	}
}

// go test -v -bench=^BenchmarkHMAC_SHA256$ -benchtime=1s hash_test.go
func BenchmarkHMAC_SHA256(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hmac.SHA256(hmacBenchData, hmacBenchKey, encoding.None)
	}
}

// go test -v -bench=^BenchmarkHMAC_SHA384$ -benchtime=1s hash_test.go
func BenchmarkHMAC_SHA384(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hmac.SHA384(hmacBenchData, hmacBenchKey, encoding.None)
	}
}

// go test -v -bench=^BenchmarkHMAC_SHA512$ -benchtime=1s hash_test.go
func BenchmarkHMAC_SHA512(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hmac.SHA512(hmacBenchData, hmacBenchKey, encoding.None)
	}
}
