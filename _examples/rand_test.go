// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/FishGoddess/cryptox/bytes/rand"
)

// go test -v -cover -run=^$ -bench=^BenchmarkBytes$
func BenchmarkBytes(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rand.Bytes(16)
	}
}

// go test -v -cover -run=^$ -bench=^BenchmarkString$
func BenchmarkString(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rand.String(16)
	}
}
