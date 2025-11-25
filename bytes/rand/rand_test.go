// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rand

import (
	"testing"
)

// go test -v -cover -run=^TestAppendBytes$
func TestAppendBytes(t *testing.T) {
	n := 32

	for i := 0; i < 10; i++ {
		bs := make([]byte, 0, n)
		bs = AppendBytes(bs, n)

		if len(bs) != n {
			t.Fatalf("len(bs) %d != n %d", len(bs), n)
		}

		t.Logf("%s\n", bs)
	}
}

// go test -v -cover -run=^TestBytes$
func TestBytes(t *testing.T) {
	for i := 1; i <= 64; i++ {
		bs := Bytes(i)

		if len(bs) != i {
			t.Fatalf("len(bs) %d != %d", len(bs), i)
		}

		t.Logf("%s\n", bs)
	}
}

// go test -v -cover -run=^TestString$
func TestString(t *testing.T) {
	for i := 1; i <= 64; i++ {
		str := String(i)

		if len(str) != i {
			t.Fatalf("len(str) %d != %d", len(str), i)
		}

		t.Logf("%s\n", str)
	}
}
