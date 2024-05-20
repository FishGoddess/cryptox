// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package aes

import (
	"testing"

	"github.com/FishGoddess/cryptox"
)

// go test -v -cover -count=1 -test.cpu=1 -run=^TestAESECB$
func TestAESECB(t *testing.T) {
	aes := New(testKey)

	cases := map[string]*testResult{
		"": {
			bs:           []byte{254, 194, 2, 244, 7, 195, 25, 158, 172, 88, 119, 145, 234, 39, 193, 11},
			hexString:    "fec202f407c3199eac587791ea27c10b",
			base64String: "/sIC9AfDGZ6sWHeR6ifBCw==",
		},
		"123": {
			bs:           []byte{106, 180, 23, 31, 55, 116, 164, 43, 132, 49, 25, 42, 117, 236, 143, 154},
			hexString:    "6ab4171f3774a42b8431192a75ec8f9a",
			base64String: "arQXHzd0pCuEMRkqdeyPmg==",
		},
		"你好，世界": {
			bs:           []byte{100, 112, 82, 33, 74, 230, 164, 206, 182, 33, 100, 255, 171, 204, 229, 193},
			hexString:    "647052214ae6a4ceb62164ffabcce5c1",
			base64String: "ZHBSIUrmpM62IWT/q8zlwQ==",
		},
	}

	for input, expect := range cases {
		crypted, err := aes.EncryptECB(cryptox.PaddingPKCS7, []byte(input))
		if err != nil {
			t.Fatal(err)
		}

		if err = expect.compareTo(crypted); err != nil {
			t.Fatal(err)
		}

		plain, err := aes.DecryptECB(cryptox.UnPaddingPKCS7, crypted)
		if err != nil {
			t.Fatal(err)
		}

		if string(plain) != input {
			t.Fatalf("input %s: plain %+v != input %+v", input, plain, []byte(input))
		}
	}
}
