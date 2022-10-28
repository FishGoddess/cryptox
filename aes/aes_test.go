// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package aes

import (
	"testing"

	"github.com/FishGoddess/cryptox"
)

var (
	testKey = []byte("123456788765432112345678")
	testIV  = []byte("8765432112345678")
)

// go test -v -cover -run=^TestWithECB$
func TestWithECB(t *testing.T) {
	encrypter := ECBEncrypter(testKey, cryptox.PaddingPKCS7)
	decrypter := ECBDecrypter(testKey, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      string([]byte{254, 194, 2, 244, 7, 195, 25, 158, 172, 88, 119, 145, 234, 39, 193, 11}),
		"123":   string([]byte{106, 180, 23, 31, 55, 116, 164, 43, 132, 49, 25, 42, 117, 236, 143, 154}),
		"你好，世界": string([]byte{100, 112, 82, 33, 74, 230, 164, 206, 182, 33, 100, 255, 171, 204, 229, 193}),
	}

	for input, expect := range cases {
		crypted, err := encrypter.Encrypt([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if string(crypted) != expect {
			t.Errorf("input %s: crypted %+v != expect %+v", input, crypted, []byte(expect))
		}

		plain, err := decrypter.Decrypt(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("input %s: plain %+v != input %+v", input, plain, []byte(input))
		}
	}
}

// go test -v -cover -run=^TestECBHex$
func TestECBHex(t *testing.T) {
	encrypter := ECBEncrypter(testKey, cryptox.PaddingPKCS7)
	decrypter := ECBDecrypter(testKey, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      "fec202f407c3199eac587791ea27c10b",
		"123":   "6ab4171f3774a42b8431192a75ec8f9a",
		"你好，世界": "647052214ae6a4ceb62164ffabcce5c1",
	}

	for input, expect := range cases {
		crypted, err := encrypter.EncryptHex([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("input %s: crypted %s != expect %+v", input, crypted, expect)
		}

		plain, err := decrypter.DecryptHex(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("expect %s: plain %s != input %s", expect, string(plain), input)
		}
	}
}

// go test -v -cover -run=^TestECBBase64$
func TestECBBase64(t *testing.T) {
	encrypter := ECBEncrypter(testKey, cryptox.PaddingPKCS7)
	decrypter := ECBDecrypter(testKey, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      "/sIC9AfDGZ6sWHeR6ifBCw==",
		"123":   "arQXHzd0pCuEMRkqdeyPmg==",
		"你好，世界": "ZHBSIUrmpM62IWT/q8zlwQ==",
	}

	for input, expect := range cases {
		crypted, err := encrypter.EncryptBase64([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("input %s: crypted %s != expect %+v", input, crypted, expect)
		}

		plain, err := decrypter.DecryptBase64(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("expect %s: plain %s != input %s", expect, string(plain), input)
		}
	}
}

// go test -v -cover -run=^TestCBC$
func TestCBC(t *testing.T) {
	encrypter := CBCEncrypter(testKey, testIV, cryptox.PaddingPKCS7)
	decrypter := CBCDecrypter(testKey, testIV, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      string([]byte{18, 228, 65, 237, 113, 28, 196, 195, 209, 118, 249, 189, 134, 92, 184, 59}),
		"123":   string([]byte{239, 166, 198, 112, 30, 48, 8, 15, 67, 248, 202, 52, 213, 118, 239, 235}),
		"你好，世界": string([]byte{31, 24, 138, 155, 181, 90, 114, 79, 168, 189, 154, 134, 242, 22, 7, 90}),
	}

	for input, expect := range cases {
		crypted, err := encrypter.Encrypt([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if string(crypted) != expect {
			t.Errorf("input %s: crypted %+v != expect %+v", input, crypted, []byte(expect))
		}

		plain, err := decrypter.Decrypt(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("input %s: plain %+v != input %+v", input, plain, []byte(input))
		}
	}
}

// go test -v -cover -run=^TestCBCHex$
func TestCBCHex(t *testing.T) {
	encrypter := CBCEncrypter(testKey, testIV, cryptox.PaddingPKCS7)
	decrypter := CBCDecrypter(testKey, testIV, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      "12e441ed711cc4c3d176f9bd865cb83b",
		"123":   "efa6c6701e30080f43f8ca34d576efeb",
		"你好，世界": "1f188a9bb55a724fa8bd9a86f216075a",
	}

	for input, expect := range cases {
		crypted, err := encrypter.EncryptHex([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("input %s: crypted %s != expect %+v", input, crypted, expect)
		}

		plain, err := decrypter.DecryptHex(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("expect %s: plain %s != input %s", expect, string(plain), input)
		}
	}
}

// go test -v -cover -run=^TestCBCBase64$
func TestCBCBase64(t *testing.T) {
	encrypter := CBCEncrypter(testKey, testIV, cryptox.PaddingPKCS7)
	decrypter := CBCDecrypter(testKey, testIV, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      "EuRB7XEcxMPRdvm9hly4Ow==",
		"123":   "76bGcB4wCA9D+Mo01Xbv6w==",
		"你好，世界": "HxiKm7Vack+ovZqG8hYHWg==",
	}

	for input, expect := range cases {
		crypted, err := encrypter.EncryptBase64([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("input %s: crypted %s != expect %+v", input, crypted, expect)
		}

		plain, err := decrypter.DecryptBase64(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("expect %s: plain %s != input %s", expect, string(plain), input)
		}
	}
}

// go test -v -cover -run=^TestCFB$
func TestCFB(t *testing.T) {
	encrypter := CFBEncrypter(testKey, testIV, cryptox.PaddingPKCS7)
	decrypter := CFBDecrypter(testKey, testIV, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      string([]byte{129, 42, 238, 182, 0, 143, 73, 239, 33, 57, 26, 89, 78, 230, 185, 139}),
		"123":   string([]byte{160, 8, 205, 171, 29, 146, 84, 242, 60, 36, 7, 68, 83, 251, 164, 150}),
		"你好，世界": string([]byte{117, 135, 94, 67, 181, 34, 182, 67, 189, 205, 178, 223, 185, 99, 37, 154}),
	}

	for input, expect := range cases {
		crypted, err := encrypter.Encrypt([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if string(crypted) != expect {
			t.Errorf("input %s: crypted %+v != expect %+v", input, crypted, []byte(expect))
		}

		plain, err := decrypter.Decrypt(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("input %s: plain %+v != input %+v", input, plain, []byte(input))
		}
	}
}

// go test -v -cover -run=^TestCFBHex$
func TestCFBHex(t *testing.T) {
	encrypter := CFBEncrypter(testKey, testIV, cryptox.PaddingPKCS7)
	decrypter := CFBDecrypter(testKey, testIV, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      "812aeeb6008f49ef21391a594ee6b98b",
		"123":   "a008cdab1d9254f23c24074453fba496",
		"你好，世界": "75875e43b522b643bdcdb2dfb963259a",
	}

	for input, expect := range cases {
		crypted, err := encrypter.EncryptHex([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("input %s: crypted %s != expect %+v", input, crypted, expect)
		}

		plain, err := decrypter.DecryptHex(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("expect %s: plain %s != input %s", expect, string(plain), input)
		}
	}
}

// go test -v -cover -run=^TestCFBBase64$
func TestCFBBase64(t *testing.T) {
	encrypter := CFBEncrypter(testKey, testIV, cryptox.PaddingPKCS7)
	decrypter := CFBDecrypter(testKey, testIV, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      "gSrutgCPSe8hORpZTua5iw==",
		"123":   "oAjNqx2SVPI8JAdEU/uklg==",
		"你好，世界": "dYdeQ7UitkO9zbLfuWMlmg==",
	}

	for input, expect := range cases {
		crypted, err := encrypter.EncryptBase64([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("input %s: crypted %s != expect %+v", input, crypted, expect)
		}

		plain, err := decrypter.DecryptBase64(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("expect %s: plain %s != input %s", expect, string(plain), input)
		}
	}
}

// go test -v -cover -run=^TestOFB$
func TestOFB(t *testing.T) {
	encrypter := OFBEncrypter(testKey, testIV, cryptox.PaddingPKCS7)
	decrypter := OFBDecrypter(testKey, testIV, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      string([]byte{129, 42, 238, 182, 0, 143, 73, 239, 33, 57, 26, 89, 78, 230, 185, 139}),
		"123":   string([]byte{160, 8, 205, 171, 29, 146, 84, 242, 60, 36, 7, 68, 83, 251, 164, 150}),
		"你好，世界": string([]byte{117, 135, 94, 67, 181, 34, 182, 67, 189, 205, 178, 223, 185, 99, 37, 154}),
	}

	for input, expect := range cases {
		crypted, err := encrypter.Encrypt([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if string(crypted) != expect {
			t.Errorf("input %s: crypted %+v != expect %+v", input, crypted, []byte(expect))
		}

		plain, err := decrypter.Decrypt(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("input %s: plain %+v != input %+v", input, plain, []byte(input))
		}
	}
}

// go test -v -cover -run=^TestOFBHex$
func TestOFBHex(t *testing.T) {
	encrypter := OFBEncrypter(testKey, testIV, cryptox.PaddingPKCS7)
	decrypter := OFBDecrypter(testKey, testIV, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      "812aeeb6008f49ef21391a594ee6b98b",
		"123":   "a008cdab1d9254f23c24074453fba496",
		"你好，世界": "75875e43b522b643bdcdb2dfb963259a",
	}

	for input, expect := range cases {
		crypted, err := encrypter.EncryptHex([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("input %s: crypted %s != expect %+v", input, crypted, expect)
		}

		plain, err := decrypter.DecryptHex(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("expect %s: plain %s != input %s", expect, string(plain), input)
		}
	}
}

// go test -v -cover -run=^TestOFBBase64$
func TestOFBBase64(t *testing.T) {
	encrypter := OFBEncrypter(testKey, testIV, cryptox.PaddingPKCS7)
	decrypter := OFBDecrypter(testKey, testIV, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      "gSrutgCPSe8hORpZTua5iw==",
		"123":   "oAjNqx2SVPI8JAdEU/uklg==",
		"你好，世界": "dYdeQ7UitkO9zbLfuWMlmg==",
	}

	for input, expect := range cases {
		crypted, err := encrypter.EncryptBase64([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("input %s: crypted %s != expect %+v", input, crypted, expect)
		}

		plain, err := decrypter.DecryptBase64(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("expect %s: plain %s != input %s", expect, string(plain), input)
		}
	}
}

// go test -v -cover -run=^TestCTR$
func TestCTR(t *testing.T) {
	encrypter := CTREncrypter(testKey, testIV, cryptox.PaddingPKCS7)
	decrypter := CTRDecrypter(testKey, testIV, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      string([]byte{129, 42, 238, 182, 0, 143, 73, 239, 33, 57, 26, 89, 78, 230, 185, 139}),
		"123":   string([]byte{160, 8, 205, 171, 29, 146, 84, 242, 60, 36, 7, 68, 83, 251, 164, 150}),
		"你好，世界": string([]byte{117, 135, 94, 67, 181, 34, 182, 67, 189, 205, 178, 223, 185, 99, 37, 154}),
	}

	for input, expect := range cases {
		crypted, err := encrypter.Encrypt([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if string(crypted) != expect {
			t.Errorf("input %s: crypted %+v != expect %+v", input, crypted, []byte(expect))
		}

		plain, err := decrypter.Decrypt(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("input %s: plain %+v != input %+v", input, plain, []byte(input))
		}
	}
}

// go test -v -cover -run=^TestCTRHex$
func TestCTRHex(t *testing.T) {
	encrypter := CTREncrypter(testKey, testIV, cryptox.PaddingPKCS7)
	decrypter := CTRDecrypter(testKey, testIV, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      "812aeeb6008f49ef21391a594ee6b98b",
		"123":   "a008cdab1d9254f23c24074453fba496",
		"你好，世界": "75875e43b522b643bdcdb2dfb963259a",
	}

	for input, expect := range cases {
		crypted, err := encrypter.EncryptHex([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("input %s: crypted %s != expect %+v", input, crypted, expect)
		}

		plain, err := decrypter.DecryptHex(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("expect %s: plain %s != input %s", expect, string(plain), input)
		}
	}
}

// go test -v -cover -run=^TestCTRBase64$
func TestCTRBase64(t *testing.T) {
	encrypter := CTREncrypter(testKey, testIV, cryptox.PaddingPKCS7)
	decrypter := CTRDecrypter(testKey, testIV, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      "gSrutgCPSe8hORpZTua5iw==",
		"123":   "oAjNqx2SVPI8JAdEU/uklg==",
		"你好，世界": "dYdeQ7UitkO9zbLfuWMlmg==",
	}

	for input, expect := range cases {
		crypted, err := encrypter.EncryptBase64([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("input %s: crypted %s != expect %+v", input, crypted, expect)
		}

		plain, err := decrypter.DecryptBase64(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("expect %s: plain %s != input %s", expect, string(plain), input)
		}
	}
}
