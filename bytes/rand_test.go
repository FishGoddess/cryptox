// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package bytes

import (
	"testing"
)

// go test -v -cover -count=1 -test.cpu=1 -run=^TestGenerateToBytes$
func TestGenerateToBytes(t *testing.T) {
	n := 32

	for i := 0; i < 10; i++ {
		bs := make([]byte, 0, n)
		bs = GenerateToBytes(bs, n)

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

// go test -v -cover -count=1 -test.cpu=1 -run=^TestGenerateString$
func TestGenerateString(t *testing.T) {
	n := 32

	for i := 0; i < 10; i++ {
		str := GenerateString(n)

		if str == "" {
			t.Error("str is wrong")
		}

		if len(str) != n {
			t.Fatalf(" len(str) %d != n %d", len(str), n)
		}

		t.Logf("%s\n", str)
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^$ -bench=^BenchmarkGenerateString$
// BenchmarkGenerateString-2       11110136               106.2 ns/op            16 B/op          1 allocs/op
func BenchmarkGenerateString(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		GenerateString(16)
	}
}
