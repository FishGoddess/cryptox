// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/FishGoddess/cryptox"
	"github.com/FishGoddess/cryptox/hash"
)

var (
	benchData = []byte("你好，世界")
)

// go test -v -bench=^BenchmarkMD5$ -benchtime=1s hash_test.go
func BenchmarkMD5(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.MD5(benchData)
	}
}

// go test -v -bench=^BenchmarkSHA1$ -benchtime=1s hash_test.go
func BenchmarkSHA1(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.SHA1(benchData)
	}
}

// go test -v -bench=^BenchmarkSHA224$ -benchtime=1s hash_test.go
func BenchmarkSHA224(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.SHA224(benchData)
	}
}

// go test -v -bench=^BenchmarkSHA256$ -benchtime=1s hash_test.go
func BenchmarkSHA256(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.SHA256(benchData)
	}
}

// go test -v -bench=^BenchmarkSHA384$ -benchtime=1s hash_test.go
func BenchmarkSHA384(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.SHA384(benchData)
	}
}

// go test -v -bench=^BenchmarkSHA512$ -benchtime=1s hash_test.go
func BenchmarkSHA512(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.SHA512(benchData)
	}
}

// go test -v -bench=^BenchmarkHMAC$ -benchtime=1s hash_test.go
func BenchmarkHMAC(b *testing.B) {
	key := []byte("12345678")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.HMAC(cryptox.SHA256, key, benchData)
	}
}
