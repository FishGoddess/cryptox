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
		bs := Bytes(i)

		for _, b := range bs {
			index := bytes.IndexByte(words, b)
			if index < 0 {
				t.Fatalf("b %+v not in words %+v", b, words)
			}
		}

		t.Logf("%s\n", bs)
	}
}

// go test -v -cover -run=^TestString$
func TestString(t *testing.T) {
	for i := 1; i <= 64; i++ {
		str := String(i)

		for _, r := range str {
			index := bytes.IndexRune(words, r)
			if index < 0 {
				t.Fatalf("b %+v not in words %+v", r, words)
			}
		}

		t.Logf("%s\n", str)
	}
}
