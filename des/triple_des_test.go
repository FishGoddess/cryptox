// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package des

import (
	"crypto/des"
	"testing"

	"github.com/FishGoddess/cryptox"
)

var (
	testTripleKey = []byte("123456788765432112345678")
)

// go test -v -cover -count=1 -test.cpu=1 -run=^TestNewTripleBlock$
func TestNewTripleBlock(t *testing.T) {
	block, blockSize, err := newTripleBlock(testTripleKey)
	if err != nil {
		t.Fatal(err)
	}

	if block == nil {
		t.Fatal("block == nil")
	}

	if blockSize != block.BlockSize() {
		t.Fatalf("blockSize %d != block.BlockSize() %d", blockSize, block.BlockSize())
	}

	wantBlock, err := des.NewTripleDESCipher(testTripleKey)
	if err != nil {
		t.Fatal(err)
	}

	if blockSize != wantBlock.BlockSize() {
		t.Fatalf("blockSize %d != wantBlock.BlockSize() %d", blockSize, wantBlock.BlockSize())
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestTripleECB$
func TestTripleECB(t *testing.T) {
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
		encrypted, err := EncryptECBTriple(testTripleKey, cryptox.PaddingPKCS7, []byte(input))
		if err != nil {
			t.Fatal(err)
		}

		if err = expect.compareTo(encrypted); err != nil {
			t.Fatal(err)
		}

		decrypted, err := DecryptECBTriple(testTripleKey, cryptox.PaddingPKCS7, encrypted)
		if err != nil {
			t.Fatal(err)
		}

		if string(decrypted) != input {
			t.Fatalf("input %s: decrypted %+v != input %+v", input, decrypted, []byte(input))
		}
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestTripleCBC$
func TestTripleCBC(t *testing.T) {
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
		encrypted, err := EncryptCBCTriple(testTripleKey, testIV, cryptox.PaddingPKCS7, []byte(input))
		if err != nil {
			t.Fatal(err)
		}

		if err = expect.compareTo(encrypted); err != nil {
			t.Fatal(err)
		}

		decrypted, err := DecryptCBCTriple(testTripleKey, testIV, cryptox.PaddingPKCS7, encrypted)
		if err != nil {
			t.Fatal(err)
		}

		if string(decrypted) != input {
			t.Fatalf("input %s: decrypted %+v != input %+v", input, decrypted, []byte(input))
		}
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestTripleCFB$
func TestTripleCFB(t *testing.T) {
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
		encrypted, err := EncryptCFBTriple(testTripleKey, testIV, cryptox.PaddingPKCS7, []byte(input))
		if err != nil {
			t.Fatal(err)
		}

		if err = expect.compareTo(encrypted); err != nil {
			t.Fatal(err)
		}

		decrypted, err := DecryptCFBTriple(testTripleKey, testIV, cryptox.PaddingPKCS7, encrypted)
		if err != nil {
			t.Fatal(err)
		}

		if string(decrypted) != input {
			t.Fatalf("input %s: decrypted %+v != input %+v", input, decrypted, []byte(input))
		}
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestTripleOFB$
func TestTripleOFB(t *testing.T) {
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
			bs:           []byte{176, 28, 68, 100, 166, 67, 156, 148, 46, 244, 26, 37, 38, 97, 62, 68},
			hexString:    "b01c4464a6439c942ef41a2526613e44",
			base64String: "sBxEZKZDnJQu9BolJmE+RA==",
		},
	}

	for input, expect := range cases {
		encrypted, err := EncryptOFBTriple(testTripleKey, testIV, cryptox.PaddingPKCS7, []byte(input))
		if err != nil {
			t.Fatal(err)
		}

		if err = expect.compareTo(encrypted); err != nil {
			t.Fatal(err)
		}

		decrypted, err := DecryptOFBTriple(testTripleKey, testIV, cryptox.PaddingPKCS7, encrypted)
		if err != nil {
			t.Fatal(err)
		}

		if string(decrypted) != input {
			t.Fatalf("input %s: decrypted %+v != input %+v", input, decrypted, []byte(input))
		}
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestTripleCTR$
func TestTripleCTR(t *testing.T) {
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
			bs:           []byte{176, 28, 68, 100, 166, 67, 156, 148, 76, 184, 154, 31, 42, 134, 28, 205},
			hexString:    "b01c4464a6439c944cb89a1f2a861ccd",
			base64String: "sBxEZKZDnJRMuJofKoYczQ==",
		},
	}

	for input, expect := range cases {
		encrypted, err := EncryptCTRTriple(testTripleKey, testIV, cryptox.PaddingPKCS7, []byte(input))
		if err != nil {
			t.Fatal(err)
		}

		if err = expect.compareTo(encrypted); err != nil {
			t.Fatal(err)
		}

		decrypted, err := DecryptCTRTriple(testTripleKey, testIV, cryptox.PaddingPKCS7, encrypted)
		if err != nil {
			t.Fatal(err)
		}

		if string(decrypted) != input {
			t.Fatalf("input %s: decrypted %+v != input %+v", input, decrypted, []byte(input))
		}
	}
}
