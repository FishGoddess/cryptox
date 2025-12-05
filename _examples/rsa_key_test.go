// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/FishGoddess/cryptox/rsa"
)

// go test -v -bench=^BenchmarkRSA_GenerateKeys1024$ -benchtime=1s rsa_key_test.go
func BenchmarkRSA_GenerateKeys1024(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, err := rsa.GenerateKeys(1024)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSA_GenerateKeys2048$ -benchtime=1s rsa_key_test.go
func BenchmarkRSA_GenerateKeys2048(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, err := rsa.GenerateKeys(2048)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSA_GenerateKeys4096$ -benchtime=1s rsa_key_test.go
func BenchmarkRSA_GenerateKeys4096(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, err := rsa.GenerateKeys(4096)
		if err != nil {
			b.Fatal(err)
		}
	}
}
