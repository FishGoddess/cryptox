// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/FishGoddess/cryptox/bytes/encoding"
	"github.com/FishGoddess/cryptox/hash"
)

var (
	benchData = []byte("你好，世界")
)

// go test -v -bench=^BenchmarkHash_MD5$ -benchtime=1s hash_test.go
func BenchmarkHash_MD5(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.MD5(benchData, encoding.None)
	}
}

// go test -v -bench=^BenchmarkHash_SHA1$ -benchtime=1s hash_test.go
func BenchmarkHash_SHA1(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.SHA1(benchData, encoding.None)
	}
}

// go test -v -bench=^BenchmarkHash_SHA224$ -benchtime=1s hash_test.go
func BenchmarkHash_SHA224(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.SHA224(benchData, encoding.None)
	}
}

// go test -v -bench=^BenchmarkHash_SHA256$ -benchtime=1s hash_test.go
func BenchmarkHash_SHA256(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.SHA256(benchData, encoding.None)
	}
}

// go test -v -bench=^BenchmarkHash_SHA384$ -benchtime=1s hash_test.go
func BenchmarkHash_SHA384(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.SHA384(benchData, encoding.None)
	}
}

// go test -v -bench=^BenchmarkHash_SHA512$ -benchtime=1s hash_test.go
func BenchmarkHash_SHA512(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.SHA512(benchData, encoding.None)
	}
}

// go test -v -bench=^BenchmarkHash_CRC32IEEE$ -benchtime=1s hash_test.go
func BenchmarkHash_CRC32IEEE(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.CRC32IEEE(benchData)
	}
}

// go test -v -bench=^BenchmarkHash_CRC64ISO$ -benchtime=1s hash_test.go
func BenchmarkHash_CRC64ISO(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.CRC64ISO(benchData)
	}
}

// go test -v -bench=^BenchmarkHash_CRC64ECMA$ -benchtime=1s hash_test.go
func BenchmarkHash_CRC64ECMA(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.CRC64ECMA(benchData)
	}
}

// go test -v -bench=^BenchmarkHash_Fnv32$ -benchtime=1s hash_test.go
func BenchmarkHash_Fnv32(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.Fnv32(benchData)
	}
}

// go test -v -bench=^BenchmarkHash_Fnv32a$ -benchtime=1s hash_test.go
func BenchmarkHash_Fnv32a(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.Fnv32a(benchData)
	}
}

// go test -v -bench=^BenchmarkHash_Fnv64$ -benchtime=1s hash_test.go
func BenchmarkHash_Fnv64(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.Fnv64(benchData)
	}
}

// go test -v -bench=^BenchmarkHash_Fnv64a$ -benchtime=1s hash_test.go
func BenchmarkHash_Fnv64a(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.Fnv64a(benchData)
	}
}

// go test -v -bench=^BenchmarkHash_Fnv128$ -benchtime=1s hash_test.go
func BenchmarkHash_Fnv128(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.Fnv128(benchData, encoding.None)
	}
}

// go test -v -bench=^BenchmarkHash_Fnv128a$ -benchtime=1s hash_test.go
func BenchmarkHash_Fnv128a(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.Fnv128a(benchData, encoding.None)
	}
}
