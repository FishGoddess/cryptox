// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package des

import (
	"crypto/des"
	"fmt"
	"testing"

	"github.com/FishGoddess/cryptox"
)

var (
	testKey = []byte("12345678")
	testIV  = []byte("87654321")
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

// go test -v -cover -count=1 -test.cpu=1 -run=^TestNewBlock$
func TestNewBlock(t *testing.T) {
	block, blockSize, err := newBlock(testKey)
	if err != nil {
		t.Fatal(err)
	}

	if block == nil {
		t.Fatal("block == nil")
	}

	if blockSize != block.BlockSize() {
		t.Fatalf("blockSize %d != block.BlockSize() %d", blockSize, block.BlockSize())
	}

	wantBlock, err := des.NewCipher(testKey)
	if err != nil {
		t.Fatal(err)
	}

	if blockSize != wantBlock.BlockSize() {
		t.Fatalf("blockSize %d != wantBlock.BlockSize() %d", blockSize, wantBlock.BlockSize())
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestECB$
func TestECB(t *testing.T) {
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
		encrypted, err := EncryptECB(testKey, cryptox.PaddingPKCS7, []byte(input))
		if err != nil {
			t.Fatal(err)
		}

		if err = expect.compareTo(encrypted); err != nil {
			t.Fatal(err)
		}

		decrypted, err := DecryptECB(testKey, cryptox.PaddingPKCS7, encrypted)
		if err != nil {
			t.Fatal(err)
		}

		if string(decrypted) != input {
			t.Fatalf("input %s: decrypted %+v != input %+v", input, decrypted, []byte(input))
		}
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestCBC$
func TestCBC(t *testing.T) {
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
		encrypted, err := EncryptCBC(testKey, testIV, cryptox.PaddingPKCS7, []byte(input))
		if err != nil {
			t.Fatal(err)
		}

		if err = expect.compareTo(encrypted); err != nil {
			t.Fatal(err)
		}

		decrypted, err := DecryptCBC(testKey, testIV, cryptox.PaddingPKCS7, encrypted)
		if err != nil {
			t.Fatal(err)
		}

		if string(decrypted) != input {
			t.Fatalf("input %s: decrypted %+v != input %+v", input, decrypted, []byte(input))
		}
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestCFB$
func TestCFB(t *testing.T) {
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
		encrypted, err := EncryptCFB(testKey, testIV, cryptox.PaddingPKCS7, []byte(input))
		if err != nil {
			t.Fatal(err)
		}

		if err = expect.compareTo(encrypted); err != nil {
			t.Fatal(err)
		}

		decrypted, err := DecryptCFB(testKey, testIV, cryptox.PaddingPKCS7, encrypted)
		if err != nil {
			t.Fatal(err)
		}

		if string(decrypted) != input {
			t.Fatalf("input %s: decrypted %+v != input %+v", input, decrypted, []byte(input))
		}
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestOFB$
func TestOFB(t *testing.T) {
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
			bs:           []byte{220, 233, 144, 205, 62, 200, 123, 152, 169, 42, 97, 1, 193, 120, 15, 149},
			hexString:    "dce990cd3ec87b98a92a6101c1780f95",
			base64String: "3OmQzT7Ie5ipKmEBwXgPlQ==",
		},
	}

	for input, expect := range cases {
		encrypted, err := EncryptOFB(testKey, testIV, cryptox.PaddingPKCS7, []byte(input))
		if err != nil {
			t.Fatal(err)
		}

		if err = expect.compareTo(encrypted); err != nil {
			t.Fatal(err)
		}

		decrypted, err := DecryptOFB(testKey, testIV, cryptox.PaddingPKCS7, encrypted)
		if err != nil {
			t.Fatal(err)
		}

		if string(decrypted) != input {
			t.Fatalf("input %s: decrypted %+v != input %+v", input, decrypted, []byte(input))
		}
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestCTR$
func TestCTR(t *testing.T) {
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
			bs:           []byte{220, 233, 144, 205, 62, 200, 123, 152, 82, 201, 236, 67, 30, 240, 63, 228},
			hexString:    "dce990cd3ec87b9852c9ec431ef03fe4",
			base64String: "3OmQzT7Ie5hSyexDHvA/5A==",
		},
	}

	for input, expect := range cases {
		encrypted, err := EncryptCTR(testKey, testIV, cryptox.PaddingPKCS7, []byte(input))
		if err != nil {
			t.Fatal(err)
		}

		if err = expect.compareTo(encrypted); err != nil {
			t.Fatal(err)
		}

		decrypted, err := DecryptCTR(testKey, testIV, cryptox.PaddingPKCS7, encrypted)
		if err != nil {
			t.Fatal(err)
		}

		if string(decrypted) != input {
			t.Fatalf("input %s: decrypted %+v != input %+v", input, decrypted, []byte(input))
		}
	}
}
