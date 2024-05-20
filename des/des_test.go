// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package des

import (
	"fmt"
	"testing"

	"github.com/FishGoddess/cryptox"
)

var (
	testKey       = []byte("12345678")
	testKeyTriple = []byte("123456788765432112345678")
	testIV        = []byte("87654321")
)

type testResult struct {
	bs           []byte
	hexString    string
	base64String string
}

func (tr *testResult) compareTo(bs cryptox.Bytes) error {
	if string(tr.bs) != string(bs) {
		return fmt.Errorf("result bs %s != bs %s", tr.bs, bs)
	}

	if tr.hexString != bs.Hex() {
		return fmt.Errorf("result hexString %s != bs hex %s", tr.hexString, bs.Hex())
	}

	if tr.base64String != bs.Base64() {
		return fmt.Errorf("result base64String %s != bs base64 %s", tr.base64String, bs.Base64())
	}

	return nil
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestDES$
func TestDES(t *testing.T) {
	if des := New(testKey); des.err != nil {
		t.Fatal(des.err)
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestTripleDES$
func TestTripleDES(t *testing.T) {
	if des := NewTriple(testKeyTriple); des.err != nil {
		t.Fatal(des.err)
	}
}
