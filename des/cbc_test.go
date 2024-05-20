// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package des

import (
	"testing"

	"github.com/FishGoddess/cryptox"
)

// go test -v -cover -count=1 -test.cpu=1 -run=^TestDESCBC$
func TestDESCBC(t *testing.T) {
	des := New(testKey)

	cases := map[string]*testResult{
		"": {
			bs:           []byte{205, 172, 198, 131, 218, 176, 175, 188},
			hexString:    "cdacc683dab0afbc",
			base64String: "zazGg9qwr7w=",
		},
		"123": {
			bs:           []byte{243, 126, 30, 174, 181, 95, 17, 128},
			hexString:    "f37e1eaeb55f1180",
			base64String: "834errVfEYA=",
		},
		"你好，世界": {
			bs:           []byte{185, 108, 29, 112, 42, 71, 169, 240, 62, 215, 156, 154, 145, 88, 110, 10},
			hexString:    "b96c1d702a47a9f03ed79c9a91586e0a",
			base64String: "uWwdcCpHqfA+15yakVhuCg==",
		},
	}

	for input, expect := range cases {
		crypted, err := des.EncryptCBC(cryptox.PaddingPKCS7, testIV, []byte(input))
		if err != nil {
			t.Fatal(err)
		}

		if err = expect.compareTo(crypted); err != nil {
			t.Fatal(err)
		}

		plain, err := des.DecryptCBC(cryptox.UnPaddingPKCS7, testIV, crypted)
		if err != nil {
			t.Fatal(err)
		}

		if string(plain) != input {
			t.Fatalf("input %s: plain %+v != input %+v", input, plain, []byte(input))
		}
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestTripleDESCBC$
func TestTripleDESCBC(t *testing.T) {
	des := NewTriple(testKeyTriple)

	cases := map[string]*testResult{
		"": {
			bs:           []byte{39, 65, 204, 186, 76, 78, 149, 112},
			hexString:    "2741ccba4c4e9570",
			base64String: "J0HMukxOlXA=",
		},
		"123": {
			bs:           []byte{0, 247, 123, 125, 239, 59, 132, 68},
			hexString:    "00f77b7def3b8444",
			base64String: "APd7fe87hEQ=",
		},
		"你好，世界": {
			bs:           []byte{153, 124, 242, 118, 122, 226, 179, 98, 152, 158, 80, 119, 178, 247, 19, 62},
			hexString:    "997cf2767ae2b362989e5077b2f7133e",
			base64String: "mXzydnris2KYnlB3svcTPg==",
		},
	}

	for input, expect := range cases {
		crypted, err := des.EncryptCBC(cryptox.PaddingPKCS7, testIV, []byte(input))
		if err != nil {
			t.Fatal(err)
		}

		if err = expect.compareTo(crypted); err != nil {
			t.Fatal(err)
		}

		plain, err := des.DecryptCBC(cryptox.UnPaddingPKCS7, testIV, crypted)
		if err != nil {
			t.Fatal(err)
		}

		if string(plain) != input {
			t.Fatalf("input %s: plain %+v != input %+v", input, plain, []byte(input))
		}
	}
}
