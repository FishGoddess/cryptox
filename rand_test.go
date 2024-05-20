// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import (
	"testing"
)

// go test -v -cover -count=1 -test.cpu=1 -run=^TestAppendBytes$
func TestAppendBytes(t *testing.T) {
	n := 32

	for i := 0; i < 10; i++ {
		bs := make([]byte, 0, n)
		bs = AppendBytes(bs, n)

		if len(bs) != n {
			t.Fatalf(" len(bs) %d != n %d", len(bs), n)
		}

		t.Logf("%s\n", bs)
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestGenerateBytes$
func TestGenerateBytes(t *testing.T) {
	n := 32

	for i := 0; i < 10; i++ {
		bs := GenerateBytes(n)

		if len(bs) != n {
			t.Fatalf(" len(bs) %d != n %d", len(bs), n)
		}

		t.Logf("%s\n", bs)
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^$ -bench=^BenchmarkGenerateBytes$
// BenchmarkGenerateBytes-2       11110136               106.2 ns/op            16 B/op          1 allocs/op
func BenchmarkGenerateBytes(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		GenerateBytes(16)
	}
}
