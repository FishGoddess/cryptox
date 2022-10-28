// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package des

import (
	"testing"

	"github.com/FishGoddess/cryptox"
)

var (
	testKey = []byte("12345678")
	testIV  = []byte("87654321")
)

// go test -v -cover -run=^TestDESWithECB$
func TestDESWithECB(t *testing.T) {
	des := WithECB(testKey, cryptox.PaddingPKCS7, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      string([]byte{254, 185, 89, 183, 212, 100, 47, 203}),
		"123":   string([]byte{44, 56, 133, 81, 215, 244, 137, 236}),
		"你好，世界": string([]byte{109, 82, 56, 231, 116, 36, 60, 100, 116, 149, 15, 240, 198, 38, 198, 204}),
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

// go test -v -cover -run=^TestDESWithECBHex$
func TestDESWithECBHex(t *testing.T) {
	des := WithECB(testKey, cryptox.PaddingPKCS7, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      "feb959b7d4642fcb",
		"123":   "2c388551d7f489ec",
		"你好，世界": "6d5238e774243c6474950ff0c626c6cc",
	}

	for input, expect := range cases {
		crypted, err := des.EncryptHex([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("input %s: crypted %s != expect %+v", input, crypted, expect)
		}

		plain, err := des.DecryptHex(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("expect %s: plain %s != input %s", expect, string(plain), input)
		}
	}
}

// go test -v -cover -run=^TestDESWithECBBase64$
func TestDESWithECBBase64(t *testing.T) {
	des := WithECB(testKey, cryptox.PaddingPKCS7, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      "/rlZt9RkL8s=",
		"123":   "LDiFUdf0iew=",
		"你好，世界": "bVI453QkPGR0lQ/wxibGzA==",
	}

	for input, expect := range cases {
		crypted, err := des.EncryptBase64([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("input %s: crypted %s != expect %+v", input, crypted, expect)
		}

		plain, err := des.DecryptBase64(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("expect %s: plain %s != input %s", expect, string(plain), input)
		}
	}
}

// go test -v -cover -run=^TestDESWithCBC$
func TestDESWithCBC(t *testing.T) {
	des := WithCBC(testKey, testIV, cryptox.PaddingPKCS7, cryptox.UnPaddingPKCS7)

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

// go test -v -cover -run=^TestDESWithCBCHex$
func TestDESWithCBCHex(t *testing.T) {
	des := WithCBC(testKey, testIV, cryptox.PaddingPKCS7, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      "cdacc683dab0afbc",
		"123":   "f37e1eaeb55f1180",
		"你好，世界": "b96c1d702a47a9f03ed79c9a91586e0a",
	}

	for input, expect := range cases {
		crypted, err := des.EncryptHex([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("input %s: crypted %s != expect %+v", input, crypted, expect)
		}

		plain, err := des.DecryptHex(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("expect %s: plain %s != input %s", expect, string(plain), input)
		}
	}
}

// go test -v -cover -run=^TestDESWithCBCBase64$
func TestDESWithCBCBase64(t *testing.T) {
	des := WithCBC(testKey, testIV, cryptox.PaddingPKCS7, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      "zazGg9qwr7w=",
		"123":   "834errVfEYA=",
		"你好，世界": "uWwdcCpHqfA+15yakVhuCg==",
	}

	for input, expect := range cases {
		crypted, err := des.EncryptBase64([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("input %s: crypted %s != expect %+v", input, crypted, expect)
		}

		plain, err := des.DecryptBase64(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("expect %s: plain %s != input %s", expect, string(plain), input)
		}
	}
}

// go test -v -cover -run=^TestDESWithCFB$
func TestDESWithCFB(t *testing.T) {
	des := WithCFB(testKey, testIV, cryptox.PaddingPKCS7, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      string([]byte{48, 92, 56, 32, 147, 125, 156, 44}),
		"123":   string([]byte{9, 102, 3, 45, 158, 112, 145, 33}),
		"你好，世界": string([]byte{220, 233, 144, 205, 62, 200, 123, 152, 231, 237, 219, 68, 211, 43, 255, 25}),
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

// go test -v -cover -run=^TestDESWithCFBHex$
func TestDESWithCFBHex(t *testing.T) {
	des := WithCFB(testKey, testIV, cryptox.PaddingPKCS7, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      "305c3820937d9c2c",
		"123":   "0966032d9e709121",
		"你好，世界": "dce990cd3ec87b98e7eddb44d32bff19",
	}

	for input, expect := range cases {
		crypted, err := des.EncryptHex([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("input %s: crypted %s != expect %+v", input, crypted, expect)
		}

		plain, err := des.DecryptHex(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("expect %s: plain %s != input %s", expect, string(plain), input)
		}
	}
}

// go test -v -cover -run=^TestDESWithCFBBase64$
func TestDESWithCFBBase64(t *testing.T) {
	des := WithCFB(testKey, testIV, cryptox.PaddingPKCS7, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      "MFw4IJN9nCw=",
		"123":   "CWYDLZ5wkSE=",
		"你好，世界": "3OmQzT7Ie5jn7dtE0yv/GQ==",
	}

	for input, expect := range cases {
		crypted, err := des.EncryptBase64([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("input %s: crypted %s != expect %+v", input, crypted, expect)
		}

		plain, err := des.DecryptBase64(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("expect %s: plain %s != input %s", expect, string(plain), input)
		}
	}
}

// go test -v -cover -run=^TestDESWithOFB$
func TestDESWithOFB(t *testing.T) {
	des := WithOFB(testKey, testIV, cryptox.PaddingPKCS7, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      string([]byte{48, 92, 56, 32, 147, 125, 156, 44}),
		"123":   string([]byte{9, 102, 3, 45, 158, 112, 145, 33}),
		"你好，世界": string([]byte{220, 233, 144, 205, 62, 200, 123, 152, 169, 42, 97, 1, 193, 120, 15, 149}),
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

// go test -v -cover -run=^TestDESWithOFBHex$
func TestDESWithOFBHex(t *testing.T) {
	des := WithOFB(testKey, testIV, cryptox.PaddingPKCS7, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      "305c3820937d9c2c",
		"123":   "0966032d9e709121",
		"你好，世界": "dce990cd3ec87b98a92a6101c1780f95",
	}

	for input, expect := range cases {
		crypted, err := des.EncryptHex([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("input %s: crypted %s != expect %+v", input, crypted, expect)
		}

		plain, err := des.DecryptHex(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("expect %s: plain %s != input %s", expect, string(plain), input)
		}
	}
}

// go test -v -cover -run=^TestDESWithOFBBase64$
func TestDESWithOFBBase64(t *testing.T) {
	des := WithOFB(testKey, testIV, cryptox.PaddingPKCS7, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      "MFw4IJN9nCw=",
		"123":   "CWYDLZ5wkSE=",
		"你好，世界": "3OmQzT7Ie5ipKmEBwXgPlQ==",
	}

	for input, expect := range cases {
		crypted, err := des.EncryptBase64([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("input %s: crypted %s != expect %+v", input, crypted, expect)
		}

		plain, err := des.DecryptBase64(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("expect %s: plain %s != input %s", expect, string(plain), input)
		}
	}
}

// go test -v -cover -run=^TestDESWithCTR$
func TestDESWithCTR(t *testing.T) {
	des := WithCTR(testKey, testIV, cryptox.PaddingPKCS7, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      string([]byte{48, 92, 56, 32, 147, 125, 156, 44}),
		"123":   string([]byte{9, 102, 3, 45, 158, 112, 145, 33}),
		"你好，世界": string([]byte{220, 233, 144, 205, 62, 200, 123, 152, 82, 201, 236, 67, 30, 240, 63, 228}),
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

// go test -v -cover -run=^TestDESWithCTRHex$
func TestDESWithCTRHex(t *testing.T) {
	des := WithCTR(testKey, testIV, cryptox.PaddingPKCS7, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      "305c3820937d9c2c",
		"123":   "0966032d9e709121",
		"你好，世界": "dce990cd3ec87b9852c9ec431ef03fe4",
	}

	for input, expect := range cases {
		crypted, err := des.EncryptHex([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("input %s: crypted %s != expect %+v", input, crypted, expect)
		}

		plain, err := des.DecryptHex(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("expect %s: plain %s != input %s", expect, string(plain), input)
		}
	}
}

// go test -v -cover -run=^TestDESWithCTRBase64$
func TestDESWithCTRBase64(t *testing.T) {
	des := WithCTR(testKey, testIV, cryptox.PaddingPKCS7, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      "MFw4IJN9nCw=",
		"123":   "CWYDLZ5wkSE=",
		"你好，世界": "3OmQzT7Ie5hSyexDHvA/5A==",
	}

	for input, expect := range cases {
		crypted, err := des.EncryptBase64([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("input %s: crypted %s != expect %+v", input, crypted, expect)
		}

		plain, err := des.DecryptBase64(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("expect %s: plain %s != input %s", expect, string(plain), input)
		}
	}
}
