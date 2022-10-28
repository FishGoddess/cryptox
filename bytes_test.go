// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import (
	"testing"

	"github.com/FishGoddess/cryptox/base64"
	"github.com/FishGoddess/cryptox/hex"
)

// go test -v -cover -run=^TestBytes$
func TestBytes(t *testing.T) {
	str := "Hello World"

	bs := Bytes(str)
	if bs.String() != str {
		t.Errorf("bs.String() %s != str %s", bs.String(), str)
	}

	if bs.Hex() != hex.Encode(bs) {
		t.Errorf("bs.String() %s != hex.Encode(bs) %s", bs.String(), hex.Encode(bs))
	}

	if bs.Base64() != base64.Encode(bs) {
		t.Errorf("bs.String() %s != base64.Encode(bs) %s", bs.String(), base64.Encode(bs))
	}
}

// go test -v -cover -run=^TestBytesClone$
func TestBytesClone(t *testing.T) {
	bs := Bytes("Hello World")
	newSlice := bs.Clone()

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
