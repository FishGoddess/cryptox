// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rand

import (
	"bytes"
	"testing"
)

// go test -v -cover -run=^TestBytes$
func TestBytes(t *testing.T) {
	for i := 1; i <= 64; i++ {
		data := Bytes(i)
		if len(data) != i {
			t.Fatalf("len(data) %d != i %d", len(data), i)
		}

		t.Logf("%s\n", data)
	}

	for i := 1; i <= 64; i++ {
		data := Bytes(i, WithWeak())

		for _, b := range data {
			index := bytes.IndexByte(words, b)
			if index < 0 {
				t.Fatalf("b %+v not in words %+v", b, words)
			}
		}

		t.Logf("%s\n", data)
	}
}

// go test -v -cover -run=^TestString$
func TestString(t *testing.T) {
	for i := 1; i <= 64; i++ {
		str := String(i)
		if len(str) != i {
			t.Fatalf("len(str) %d != i %d", len(str), i)
		}

		t.Logf("%s\n", str)
	}

	for i := 1; i <= 64; i++ {
		str := String(i, WithWeak())

		for _, r := range str {
			index := bytes.IndexRune(words, r)
			if index < 0 {
				t.Fatalf("r %+v not in words %+v", r, words)
			}
		}

		t.Logf("%s\n", str)
	}
}
