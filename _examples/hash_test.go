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

// go test -v -bench=^BenchmarkMD5$ -benchtime=1s hash_test.go
func BenchmarkMD5(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.MD5(benchData, encoding.None)
	}
}

// go test -v -bench=^BenchmarkSHA1$ -benchtime=1s hash_test.go
func BenchmarkSHA1(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.SHA1(benchData, encoding.None)
	}
}

// go test -v -bench=^BenchmarkSHA224$ -benchtime=1s hash_test.go
func BenchmarkSHA224(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.SHA224(benchData, encoding.None)
	}
}

// go test -v -bench=^BenchmarkSHA256$ -benchtime=1s hash_test.go
func BenchmarkSHA256(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.SHA256(benchData, encoding.None)
	}
}

// go test -v -bench=^BenchmarkSHA384$ -benchtime=1s hash_test.go
func BenchmarkSHA384(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.SHA384(benchData, encoding.None)
	}
}

// go test -v -bench=^BenchmarkSHA512$ -benchtime=1s hash_test.go
func BenchmarkSHA512(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.SHA512(benchData, encoding.None)
	}
}

// go test -v -bench=^BenchmarkCRC32IEEE$ -benchtime=1s hash_test.go
func BenchmarkCRC32IEEE(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.CRC32IEEE(benchData)
	}
}

// go test -v -bench=^BenchmarkCRC64ISO$ -benchtime=1s hash_test.go
func BenchmarkCRC64ISO(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.CRC64ISO(benchData)
	}
}

// go test -v -bench=^BenchmarkCRC64ECMA$ -benchtime=1s hash_test.go
func BenchmarkCRC64ECMA(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.CRC64ECMA(benchData)
	}
}

// go test -v -bench=^BenchmarkFnv32$ -benchtime=1s hash_test.go
func BenchmarkFnv32(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.Fnv32(benchData)
	}
}

// go test -v -bench=^BenchmarkFnv32a$ -benchtime=1s hash_test.go
func BenchmarkFnv32a(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.Fnv32a(benchData)
	}
}

// go test -v -bench=^BenchmarkFnv64$ -benchtime=1s hash_test.go
func BenchmarkFnv64(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.Fnv64(benchData)
	}
}

// go test -v -bench=^BenchmarkFnv64a$ -benchtime=1s hash_test.go
func BenchmarkFnv64a(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.Fnv64a(benchData)
	}
}

// go test -v -bench=^BenchmarkFnv128$ -benchtime=1s hash_test.go
func BenchmarkFnv128(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.Fnv128(benchData, encoding.None)
	}
}

// go test -v -bench=^BenchmarkFnv128a$ -benchtime=1s hash_test.go
func BenchmarkFnv128a(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.Fnv128a(benchData, encoding.None)
	}
}
