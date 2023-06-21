// Copyright 2023 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package des

import (
	"testing"

	"github.com/FishGoddess/cryptox"
)

// go test -v -cover -run=^TestDESECB$
func TestDESECB(t *testing.T) {
	des := New(testKey)

	cases := map[string]*testResult{
		"": {
			bs:           []byte{254, 185, 89, 183, 212, 100, 47, 203},
			hexString:    "feb959b7d4642fcb",
			base64String: "/rlZt9RkL8s=",
		},
		"123": {
			bs:           []byte{44, 56, 133, 81, 215, 244, 137, 236},
			hexString:    "2c388551d7f489ec",
			base64String: "LDiFUdf0iew=",
		},
		"你好，世界": {
			bs:           []byte{109, 82, 56, 231, 116, 36, 60, 100, 116, 149, 15, 240, 198, 38, 198, 204},
			hexString:    "6d5238e774243c6474950ff0c626c6cc",
			base64String: "bVI453QkPGR0lQ/wxibGzA==",
		},
	}

	for input, expect := range cases {
		crypted, err := des.EncryptECB(cryptox.PaddingPKCS7, cryptox.FromString(input))
		if err != nil {
			t.Error(err)
		}

		if err = expect.compareTo(crypted); err != nil {
			t.Error(err)
		}

		plain, err := des.DecryptECB(cryptox.UnPaddingPKCS7, crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("input %s: plain %+v != input %+v", input, plain, []byte(input))
		}
	}
}

// go test -v -cover -run=^TestTripleDESECB$
func TestTripleDESECB(t *testing.T) {
	des := NewTriple(testKeyTriple)

	cases := map[string]*testResult{
		"": {
			bs:           []byte{163, 133, 24, 236, 31, 63, 147, 38},
			hexString:    "a38518ec1f3f9326",
			base64String: "o4UY7B8/kyY=",
		},
		"123": {
			bs:           []byte{185, 2, 158, 11, 229, 10, 126, 217},
			hexString:    "b9029e0be50a7ed9",
			base64String: "uQKeC+UKftk=",
		},
		"你好，世界": {
			bs:           []byte{224, 251, 123, 121, 70, 219, 201, 188, 14, 248, 74, 206, 42, 34, 16, 102},
			hexString:    "e0fb7b7946dbc9bc0ef84ace2a221066",
			base64String: "4Pt7eUbbybwO+ErOKiIQZg==",
		},
	}

	for input, expect := range cases {
		crypted, err := des.EncryptECB(cryptox.PaddingPKCS7, cryptox.FromString(input))
		if err != nil {
			t.Error(err)
		}

		if err = expect.compareTo(crypted); err != nil {
			t.Error(err)
		}

		plain, err := des.DecryptECB(cryptox.UnPaddingPKCS7, crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("input %s: plain %+v != input %+v", input, plain, []byte(input))
		}
	}
}
