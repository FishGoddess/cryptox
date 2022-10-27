// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package des

import (
	"testing"

	"github.com/FishGoddess/cryptox"
)

var (
	testKey       = []byte("12345678")
	testIV        = []byte("87654321")
	testPadding   = cryptox.PaddingPKCS7
	testUnPadding = cryptox.UnPaddingPKCS7
)

// go test -v -cover -run=^TestDESWithCBC$
func TestDESWithCBC(t *testing.T) {
	des := WithCBC(testKey, testIV, testPadding, testUnPadding)

	cases := map[string]string{
		"":      string([]byte{205, 172, 198, 131, 218, 176, 175, 188}),
		"123":   string([]byte{243, 126, 30, 174, 181, 95, 17, 128}),
		"你好，世界": string([]byte{185, 108, 29, 112, 42, 71, 169, 240, 62, 215, 156, 154, 145, 88, 110, 10}),
	}

	for input, expect := range cases {
		crypted, err := des.Encrypt([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if string(crypted) != expect {
			t.Errorf("input %s: crypted %+v != expect %+v", input, crypted, []byte(expect))
		}

		plain, err := des.Decrypt(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("input %s: plain %+v != input %+v", input, plain, []byte(input))
		}
	}
}
