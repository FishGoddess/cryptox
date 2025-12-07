// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/FishGoddess/cryptox/ed25519"
)

// go test -v -bench=^BenchmarkED25519_GenerateKeys$ -benchtime=1s ed25519_key_test.go
func BenchmarkED25519_GenerateKeys(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, err := ed25519.GenerateKeys()
		if err != nil {
			b.Fatal(err)
		}
	}
}
