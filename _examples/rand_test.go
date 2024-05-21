// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/FishGoddess/cryptox"
)

// go test -v -cover -count=1 -test.cpu=1 -run=^$ -bench=^BenchmarkGenerateBytes$
func BenchmarkGenerateBytes(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		cryptox.GenerateBytes(16)
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^$ -bench=^BenchmarkGenerateString$
func BenchmarkGenerateString(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		cryptox.GenerateString(16)
	}
}
