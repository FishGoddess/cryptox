// Copyright 2023 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package aes

import (
	"testing"

	"github.com/FishGoddess/cryptox"
)

// go test -v -cover -run=^TestAESCBC$
func TestAESCBC(t *testing.T) {
	aes := New(testKey)

	cases := map[string]*testResult{
		"": {
			bs:           []byte{18, 228, 65, 237, 113, 28, 196, 195, 209, 118, 249, 189, 134, 92, 184, 59},
			hexString:    "12e441ed711cc4c3d176f9bd865cb83b",
			base64String: "EuRB7XEcxMPRdvm9hly4Ow==",
		},
		"123": {
			bs:           []byte{239, 166, 198, 112, 30, 48, 8, 15, 67, 248, 202, 52, 213, 118, 239, 235},
			hexString:    "efa6c6701e30080f43f8ca34d576efeb",
			base64String: "76bGcB4wCA9D+Mo01Xbv6w==",
		},
		"你好，世界": {
			bs:           []byte{31, 24, 138, 155, 181, 90, 114, 79, 168, 189, 154, 134, 242, 22, 7, 90},
			hexString:    "1f188a9bb55a724fa8bd9a86f216075a",
			base64String: "HxiKm7Vack+ovZqG8hYHWg==",
		},
	}

	for input, expect := range cases {
		crypted, err := aes.EncryptCBC(cryptox.PaddingPKCS7, testIV, cryptox.FromString(input))
		if err != nil {
			t.Error(err)
		}

		if err = expect.compareTo(crypted); err != nil {
			t.Error(err)
		}

		plain, err := aes.DecryptCBC(cryptox.UnPaddingPKCS7, testIV, crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("input %s: plain %+v != input %+v", input, plain, []byte(input))
		}
	}
}
