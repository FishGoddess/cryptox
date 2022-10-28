// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import "testing"

// go test -v -cover -run=^TestCopyBytes$
func TestCopyBytes(t *testing.T) {
	bs := []byte("Hello World")
	newSlice := copyBytes(bs)

	if string(newSlice) != string(bs) {
		t.Errorf("newSlice %s != bs %s", string(newSlice), string(bs))
	}
}

// go test -v -cover -run=^TestRandomBytes$
func TestRandomBytes(t *testing.T) {
	for i := 0; i < 16; i++ {
		n := i

		bs, err := RandomBytes(n)
		if err != nil {
			t.Error(err)
		}

		if len(bs) != n {
			t.Errorf("len(bs) %d != n %d", len(bs), n)
		}

		t.Log(bs)
	}
}
