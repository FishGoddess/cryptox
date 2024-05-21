// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/FishGoddess/cryptox/hmac"
)

var (
	hmacBenchKey  = []byte("12345678")
	hmacBenchData = []byte("你好，世界")
)

// go test -v -bench=^BenchmarkHMACUsingMD5$ -benchtime=1s hash_test.go
func BenchmarkHMACUsingMD5(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hmac.MD5(hmacBenchKey, hmacBenchData)
	}
}

// go test -v -bench=^BenchmarkHMACUsingSHA1$ -benchtime=1s hash_test.go
func BenchmarkHMACUsingSHA1(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hmac.SHA1(hmacBenchKey, hmacBenchData)
	}
}

// go test -v -bench=^BenchmarkHMACUsingSHA224$ -benchtime=1s hash_test.go
func BenchmarkHMACUsingSHA224(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hmac.SHA224(hmacBenchKey, hmacBenchData)
	}
}

// go test -v -bench=^BenchmarkHMACUsingSHA256$ -benchtime=1s hash_test.go
func BenchmarkHMACUsingSHA256(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hmac.SHA256(hmacBenchKey, hmacBenchData)
	}
}

// go test -v -bench=^BenchmarkHMACUsingSHA384$ -benchtime=1s hash_test.go
func BenchmarkHMACUsingSHA384(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hmac.SHA384(hmacBenchKey, hmacBenchData)
	}
}

// go test -v -bench=^BenchmarkHMACUsingSHA512$ -benchtime=1s hash_test.go
func BenchmarkHMACUsingSHA512(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hmac.SHA512(hmacBenchKey, hmacBenchData)
	}
}
