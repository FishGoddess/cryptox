// Copyright 2023 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package aes

import (
	"fmt"
	"testing"

	"github.com/FishGoddess/cryptox"
)

var (
	testKey = []byte("123456788765432112345678")
	testIV  = []byte("8765432112345678")
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

// go test -v -cover -run=^TestAES$
func TestAES(t *testing.T) {
	if aes := New(testKey); aes.err != nil {
		t.Error(aes.err)
	}
}
