// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package des

import (
	"testing"

	"github.com/FishGoddess/cryptox"
)

// go test -v -cover -count=1 -test.cpu=1 -run=^TestDESCFB$
func TestDESCFB(t *testing.T) {
	des := New(testKey)

	cases := map[string]*testResult{
		"": {
			bs:           []byte{48, 92, 56, 32, 147, 125, 156, 44},
			hexString:    "305c3820937d9c2c",
			base64String: "MFw4IJN9nCw=",
		},
		"123": {
			bs:           []byte{9, 102, 3, 45, 158, 112, 145, 33},
			hexString:    "0966032d9e709121",
			base64String: "CWYDLZ5wkSE=",
		},
		"你好，世界": {
			bs:           []byte{220, 233, 144, 205, 62, 200, 123, 152, 231, 237, 219, 68, 211, 43, 255, 25},
			hexString:    "dce990cd3ec87b98e7eddb44d32bff19",
			base64String: "3OmQzT7Ie5jn7dtE0yv/GQ==",
		},
	}

	for input, expect := range cases {
		crypted, err := des.EncryptCFB(cryptox.PaddingPKCS7, testIV, []byte(input))
		if err != nil {
			t.Fatal(err)
		}

		if err = expect.compareTo(crypted); err != nil {
			t.Fatal(err)
		}

		plain, err := des.DecryptCFB(cryptox.UnPaddingPKCS7, testIV, crypted)
		if err != nil {
			t.Fatal(err)
		}

		if string(plain) != input {
			t.Fatalf("input %s: plain %+v != input %+v", input, plain, []byte(input))
		}
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestTripleDESCFB$
func TestTripleDESCFB(t *testing.T) {
	des := NewTriple(testKeyTriple)

	cases := map[string]*testResult{
		"": {
			bs:           []byte{92, 169, 236, 137, 11, 246, 123, 32},
			hexString:    "5ca9ec890bf67b20",
			base64String: "XKnsiQv2eyA=",
		},
		"123": {
			bs:           []byte{101, 147, 215, 132, 6, 251, 118, 45},
			hexString:    "6593d78406fb762d",
			base64String: "ZZPXhAb7di0=",
		},
		"你好，世界": {
			bs:           []byte{176, 28, 68, 100, 166, 67, 156, 148, 85, 69, 217, 58, 184, 136, 197, 51},
			hexString:    "b01c4464a6439c945545d93ab888c533",
			base64String: "sBxEZKZDnJRVRdk6uIjFMw==",
		},
	}

	for input, expect := range cases {
		crypted, err := des.EncryptCFB(cryptox.PaddingPKCS7, testIV, []byte(input))
		if err != nil {
			t.Fatal(err)
		}

		if err = expect.compareTo(crypted); err != nil {
			t.Fatal(err)
		}

		plain, err := des.DecryptCFB(cryptox.UnPaddingPKCS7, testIV, crypted)
		if err != nil {
			t.Fatal(err)
		}

		if string(plain) != input {
			t.Fatalf("input %s: plain %+v != input %+v", input, plain, []byte(input))
		}
	}
}
