// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package des

import (
	"testing"

	"github.com/FishGoddess/cryptox"
)

var (
	testTripleKey = []byte("123456788765432112345678")
	testTripleIV  = []byte("87654321")
)

// go test -v -cover -run=^TestTripleECB$
func TestTripleECB(t *testing.T) {
	encryptor := EncryptTripleECB(testTripleKey, cryptox.PaddingPKCS7)
	decryptor := DecryptTripleECB(testTripleKey, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      string([]byte{163, 133, 24, 236, 31, 63, 147, 38}),
		"123":   string([]byte{185, 2, 158, 11, 229, 10, 126, 217}),
		"你好，世界": string([]byte{224, 251, 123, 121, 70, 219, 201, 188, 14, 248, 74, 206, 42, 34, 16, 102}),
	}

	for input, expect := range cases {
		crypted, err := encryptor.Encrypt([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if string(crypted) != expect {
			t.Errorf("input %s: crypted %+v != expect %+v", input, crypted, []byte(expect))
		}

		plain, err := decryptor.Decrypt(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("input %s: plain %+v != input %+v", input, plain, []byte(input))
		}
	}
}

// go test -v -cover -run=^TestTripleECBHex$
func TestTripleECBHex(t *testing.T) {
	encryptor := EncryptTripleECB(testTripleKey, cryptox.PaddingPKCS7)
	decryptor := DecryptTripleECB(testTripleKey, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      "a38518ec1f3f9326",
		"123":   "b9029e0be50a7ed9",
		"你好，世界": "e0fb7b7946dbc9bc0ef84ace2a221066",
	}

	for input, expect := range cases {
		crypted, err := encryptor.EncryptHex([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("input %s: crypted %s != expect %+v", input, crypted, expect)
		}

		plain, err := decryptor.DecryptHex(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("expect %s: plain %s != input %s", expect, string(plain), input)
		}
	}
}

// go test -v -cover -run=^TestTripleECBBase64$
func TestTripleECBBase64(t *testing.T) {
	encryptor := EncryptTripleECB(testTripleKey, cryptox.PaddingPKCS7)
	decryptor := DecryptTripleECB(testTripleKey, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      "o4UY7B8/kyY=",
		"123":   "uQKeC+UKftk=",
		"你好，世界": "4Pt7eUbbybwO+ErOKiIQZg==",
	}

	for input, expect := range cases {
		crypted, err := encryptor.EncryptBase64([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("input %s: crypted %s != expect %+v", input, crypted, expect)
		}

		plain, err := decryptor.DecryptBase64(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("expect %s: plain %s != input %s", expect, string(plain), input)
		}
	}
}

// go test -v -cover -run=^TestTripleCBC$
func TestTripleCBC(t *testing.T) {
	encryptor := EncryptTripleCBC(testTripleKey, testTripleIV, cryptox.PaddingPKCS7)
	decryptor := DecryptTripleCBC(testTripleKey, testTripleIV, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      string([]byte{39, 65, 204, 186, 76, 78, 149, 112}),
		"123":   string([]byte{0, 247, 123, 125, 239, 59, 132, 68}),
		"你好，世界": string([]byte{153, 124, 242, 118, 122, 226, 179, 98, 152, 158, 80, 119, 178, 247, 19, 62}),
	}

	for input, expect := range cases {
		crypted, err := encryptor.Encrypt([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if string(crypted) != expect {
			t.Errorf("input %s: crypted %+v != expect %+v", input, crypted, []byte(expect))
		}

		plain, err := decryptor.Decrypt(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("input %s: plain %+v != input %+v", input, plain, []byte(input))
		}
	}
}

// go test -v -cover -run=^TestTripleCBCHex$
func TestTripleCBCHex(t *testing.T) {
	encryptor := EncryptTripleCBC(testTripleKey, testTripleIV, cryptox.PaddingPKCS7)
	decryptor := DecryptTripleCBC(testTripleKey, testTripleIV, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      "2741ccba4c4e9570",
		"123":   "00f77b7def3b8444",
		"你好，世界": "997cf2767ae2b362989e5077b2f7133e",
	}

	for input, expect := range cases {
		crypted, err := encryptor.EncryptHex([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("input %s: crypted %s != expect %+v", input, crypted, expect)
		}

		plain, err := decryptor.DecryptHex(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("expect %s: plain %s != input %s", expect, string(plain), input)
		}
	}
}

// go test -v -cover -run=^TestTripleCBCBase64$
func TestTripleCBCBase64(t *testing.T) {
	encryptor := EncryptTripleCBC(testTripleKey, testTripleIV, cryptox.PaddingPKCS7)
	decryptor := DecryptTripleCBC(testTripleKey, testTripleIV, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      "J0HMukxOlXA=",
		"123":   "APd7fe87hEQ=",
		"你好，世界": "mXzydnris2KYnlB3svcTPg==",
	}

	for input, expect := range cases {
		crypted, err := encryptor.EncryptBase64([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("input %s: crypted %s != expect %+v", input, crypted, expect)
		}

		plain, err := decryptor.DecryptBase64(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("expect %s: plain %s != input %s", expect, string(plain), input)
		}
	}
}

// go test -v -cover -run=^TestTripleCFB$
func TestTripleCFB(t *testing.T) {
	encryptor := EncryptTripleCFB(testTripleKey, testTripleIV, cryptox.PaddingPKCS7)
	decryptor := DecryptTripleCFB(testTripleKey, testTripleIV, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      string([]byte{92, 169, 236, 137, 11, 246, 123, 32}),
		"123":   string([]byte{101, 147, 215, 132, 6, 251, 118, 45}),
		"你好，世界": string([]byte{176, 28, 68, 100, 166, 67, 156, 148, 85, 69, 217, 58, 184, 136, 197, 51}),
	}

	for input, expect := range cases {
		crypted, err := encryptor.Encrypt([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if string(crypted) != expect {
			t.Errorf("input %s: crypted %+v != expect %+v", input, crypted, []byte(expect))
		}

		plain, err := decryptor.Decrypt(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("input %s: plain %+v != input %+v", input, plain, []byte(input))
		}
	}
}

// go test -v -cover -run=^TestTripleCFBHex$
func TestTripleCFBHex(t *testing.T) {
	encryptor := EncryptTripleCFB(testTripleKey, testTripleIV, cryptox.PaddingPKCS7)
	decryptor := DecryptTripleCFB(testTripleKey, testTripleIV, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      "5ca9ec890bf67b20",
		"123":   "6593d78406fb762d",
		"你好，世界": "b01c4464a6439c945545d93ab888c533",
	}

	for input, expect := range cases {
		crypted, err := encryptor.EncryptHex([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("input %s: crypted %s != expect %+v", input, crypted, expect)
		}

		plain, err := decryptor.DecryptHex(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("expect %s: plain %s != input %s", expect, string(plain), input)
		}
	}
}

// go test -v -cover -run=^TestTripleCFBBase64$
func TestTripleCFBBase64(t *testing.T) {
	encryptor := EncryptTripleCFB(testTripleKey, testTripleIV, cryptox.PaddingPKCS7)
	decryptor := DecryptTripleCFB(testTripleKey, testTripleIV, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      "XKnsiQv2eyA=",
		"123":   "ZZPXhAb7di0=",
		"你好，世界": "sBxEZKZDnJRVRdk6uIjFMw==",
	}

	for input, expect := range cases {
		crypted, err := encryptor.EncryptBase64([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("input %s: crypted %s != expect %+v", input, crypted, expect)
		}

		plain, err := decryptor.DecryptBase64(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("expect %s: plain %s != input %s", expect, string(plain), input)
		}
	}
}

// go test -v -cover -run=^TestTripleOFB$
func TestTripleOFB(t *testing.T) {
	encryptor := EncryptTripleOFB(testTripleKey, testTripleIV, cryptox.PaddingPKCS7)
	decryptor := DecryptTripleOFB(testTripleKey, testTripleIV, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      string([]byte{92, 169, 236, 137, 11, 246, 123, 32}),
		"123":   string([]byte{101, 147, 215, 132, 6, 251, 118, 45}),
		"你好，世界": string([]byte{176, 28, 68, 100, 166, 67, 156, 148, 46, 244, 26, 37, 38, 97, 62, 68}),
	}

	for input, expect := range cases {
		crypted, err := encryptor.Encrypt([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if string(crypted) != expect {
			t.Errorf("input %s: crypted %+v != expect %+v", input, crypted, []byte(expect))
		}

		plain, err := decryptor.Decrypt(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("input %s: plain %+v != input %+v", input, plain, []byte(input))
		}
	}
}

// go test -v -cover -run=^TestTripleOFBHex$
func TestTripleOFBHex(t *testing.T) {
	encryptor := EncryptTripleOFB(testTripleKey, testTripleIV, cryptox.PaddingPKCS7)
	decryptor := DecryptTripleOFB(testTripleKey, testTripleIV, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      "5ca9ec890bf67b20",
		"123":   "6593d78406fb762d",
		"你好，世界": "b01c4464a6439c942ef41a2526613e44",
	}

	for input, expect := range cases {
		crypted, err := encryptor.EncryptHex([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("input %s: crypted %s != expect %+v", input, crypted, expect)
		}

		plain, err := decryptor.DecryptHex(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("expect %s: plain %s != input %s", expect, string(plain), input)
		}
	}
}

// go test -v -cover -run=^TestTripleOFBBase64$
func TestTripleOFBBase64(t *testing.T) {
	encryptor := EncryptTripleOFB(testTripleKey, testTripleIV, cryptox.PaddingPKCS7)
	decryptor := DecryptTripleOFB(testTripleKey, testTripleIV, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      "XKnsiQv2eyA=",
		"123":   "ZZPXhAb7di0=",
		"你好，世界": "sBxEZKZDnJQu9BolJmE+RA==",
	}

	for input, expect := range cases {
		crypted, err := encryptor.EncryptBase64([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("input %s: crypted %s != expect %+v", input, crypted, expect)
		}

		plain, err := decryptor.DecryptBase64(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("expect %s: plain %s != input %s", expect, string(plain), input)
		}
	}
}

// go test -v -cover -run=^TestTripleCTR$
func TestTripleCTR(t *testing.T) {
	encryptor := EncryptTripleCTR(testTripleKey, testTripleIV, cryptox.PaddingPKCS7)
	decryptor := DecryptTripleCTR(testTripleKey, testTripleIV, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      string([]byte{92, 169, 236, 137, 11, 246, 123, 32}),
		"123":   string([]byte{101, 147, 215, 132, 6, 251, 118, 45}),
		"你好，世界": string([]byte{176, 28, 68, 100, 166, 67, 156, 148, 76, 184, 154, 31, 42, 134, 28, 205}),
	}

	for input, expect := range cases {
		crypted, err := encryptor.Encrypt([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if string(crypted) != expect {
			t.Errorf("input %s: crypted %+v != expect %+v", input, crypted, []byte(expect))
		}

		plain, err := decryptor.Decrypt(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("input %s: plain %+v != input %+v", input, plain, []byte(input))
		}
	}
}

// go test -v -cover -run=^TestTripleCTRHex$
func TestTripleCTRHex(t *testing.T) {
	encryptor := EncryptTripleCTR(testTripleKey, testTripleIV, cryptox.PaddingPKCS7)
	decryptor := DecryptTripleCTR(testTripleKey, testTripleIV, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      "5ca9ec890bf67b20",
		"123":   "6593d78406fb762d",
		"你好，世界": "b01c4464a6439c944cb89a1f2a861ccd",
	}

	for input, expect := range cases {
		crypted, err := encryptor.EncryptHex([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("input %s: crypted %s != expect %+v", input, crypted, expect)
		}

		plain, err := decryptor.DecryptHex(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("expect %s: plain %s != input %s", expect, string(plain), input)
		}
	}
}

// go test -v -cover -run=^TestTripleCTRBase64$
func TestTripleCTRBase64(t *testing.T) {
	encryptor := EncryptTripleCTR(testTripleKey, testTripleIV, cryptox.PaddingPKCS7)
	decryptor := DecryptTripleCTR(testTripleKey, testTripleIV, cryptox.UnPaddingPKCS7)

	cases := map[string]string{
		"":      "XKnsiQv2eyA=",
		"123":   "ZZPXhAb7di0=",
		"你好，世界": "sBxEZKZDnJRMuJofKoYczQ==",
	}

	for input, expect := range cases {
		crypted, err := encryptor.EncryptBase64([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("input %s: crypted %s != expect %+v", input, crypted, expect)
		}

		plain, err := decryptor.DecryptBase64(crypted)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("expect %s: plain %s != input %s", expect, string(plain), input)
		}
	}
}
