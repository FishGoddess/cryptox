// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package aes

import (
	"testing"

	"github.com/FishGoddess/cryptox"
)

// go test -v -cover -count=1 -test.cpu=1 -run=^TestAESCFB$
func TestAESCFB(t *testing.T) {
	aes := New(testKey)

	cases := map[string]*testResult{
		"": {
			bs:           []byte{129, 42, 238, 182, 0, 143, 73, 239, 33, 57, 26, 89, 78, 230, 185, 139},
			hexString:    "812aeeb6008f49ef21391a594ee6b98b",
			base64String: "gSrutgCPSe8hORpZTua5iw==",
		},
		"123": {
			bs:           []byte{160, 8, 205, 171, 29, 146, 84, 242, 60, 36, 7, 68, 83, 251, 164, 150},
			hexString:    "a008cdab1d9254f23c24074453fba496",
			base64String: "oAjNqx2SVPI8JAdEU/uklg==",
		},
		"你好，世界": {
			bs:           []byte{117, 135, 94, 67, 181, 34, 182, 67, 189, 205, 178, 223, 185, 99, 37, 154},
			hexString:    "75875e43b522b643bdcdb2dfb963259a",
			base64String: "dYdeQ7UitkO9zbLfuWMlmg==",
		},
	}

	for input, expect := range cases {
		crypted, err := aes.EncryptCFB(cryptox.PaddingPKCS7, testIV, []byte(input))
		if err != nil {
			t.Fatal(err)
		}

		if err = expect.compareTo(crypted); err != nil {
			t.Fatal(err)
		}

		plain, err := aes.DecryptCFB(cryptox.UnPaddingPKCS7, testIV, crypted)
		if err != nil {
			t.Fatal(err)
		}

		if string(plain) != input {
			t.Fatalf("input %s: plain %+v != input %+v", input, plain, []byte(input))
		}
	}
}
