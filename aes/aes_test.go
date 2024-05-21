// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package aes

import (
	"crypto/aes"
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

	wantBlock, err := aes.NewCipher(testKey)
	if err != nil {
		t.Fatal(err)
	}

	if blockSize != wantBlock.BlockSize() {
		t.Fatalf("blockSize %d != wantBlock.BlockSize() %d", blockSize, wantBlock.BlockSize())
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestAESECB$
func TestECB(t *testing.T) {
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

// go test -v -cover -count=1 -test.cpu=1 -run=^TestGCM$
func TestGCM(t *testing.T) {
	cases := map[string]*testResult{
		"123": {
			bs:           []byte{249, 132, 42, 40, 152, 17, 118, 4, 46, 97, 216, 169, 163, 62, 71, 150, 67, 189, 73},
			hexString:    "f9842a28981176042e61d8a9a33e479643bd49",
			base64String: "+YQqKJgRdgQuYdipoz5HlkO9SQ==",
		},
		"你好，世界": {
			bs:           []byte{44, 11, 185, 159, 152, 100, 94, 1, 82, 180, 112, 131, 14, 35, 63, 39, 98, 215, 167, 243, 173, 80, 155, 27, 228, 197, 155, 234, 236, 204, 91},
			hexString:    "2c0bb99f98645e0152b470830e233f2762d7a7f3ad509b1be4c59beaeccc5b",
			base64String: "LAu5n5hkXgFStHCDDiM/J2LXp/OtUJsb5MWb6uzMWw==",
		},
	}

	nonce := []byte("123456abcdef")
	for input, expect := range cases {
		encrypted, err := EncryptGCM(testKey, nonce, nil, []byte(input))
		if err != nil {
			t.Fatal(err)
		}

		if err = expect.compareTo(encrypted); err != nil {
			t.Fatal(err)
		}

		decrypted, err := DecryptGCM(testKey, nonce, nil, encrypted)
		if err != nil {
			t.Fatal(err)
		}

		if string(decrypted) != input {
			t.Fatalf("input %s: decrypted %+v != input %+v", input, decrypted, []byte(input))
		}
	}
}
