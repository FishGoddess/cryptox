// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package des

import (
	"testing"

	"github.com/FishGoddess/cryptox"
)

// go test -v -cover -run=^TestDESEncryptECB$
func TestDESEncryptECB(t *testing.T) {
	des := New([]byte("12345678"))

	cases := map[string]string{
		"":      string([]byte{254, 185, 89, 183, 212, 100, 47, 203}),
		"123":   string([]byte{44, 56, 133, 81, 215, 244, 137, 236}),
		"你好，世界": string([]byte{109, 82, 56, 231, 116, 36, 60, 100, 116, 149, 15, 240, 198, 38, 198, 204}),
	}

	for plain, expect := range cases {
		crypted, err := des.EncryptECB([]byte(plain), cryptox.PKCS7())
		if err != nil {
			t.Error(err)
		}

		cryptoStr := string(crypted)
		if cryptoStr != expect {
			t.Errorf("plain %s: cryptoStr %+v != expect %+v", plain, crypted, []byte(expect))
		}
	}
}

// go test -v -cover -run=^TestDESEncryptECBHex$
func TestDESEncryptECBHex(t *testing.T) {
	des := New([]byte("12345678"))

	cases := map[string]string{
		"":      "feb959b7d4642fcb",
		"123":   "2c388551d7f489ec",
		"你好，世界": "6d5238e774243c6474950ff0c626c6cc",
	}

	for plain, expect := range cases {
		crypted, err := des.EncryptECBHex([]byte(plain), cryptox.PKCS7())
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("plain %s: crypted %s != expect %s", plain, crypted, expect)
		}
	}
}

// go test -v -cover -run=^TestDESEncryptECBBase64$
func TestDESEncryptECBBase64(t *testing.T) {
	des := New([]byte("12345678"))

	cases := map[string]string{
		"":      "/rlZt9RkL8s=",
		"123":   "LDiFUdf0iew=",
		"你好，世界": "bVI453QkPGR0lQ/wxibGzA==",
	}

	for plain, expect := range cases {
		crypted, err := des.EncryptECBBase64([]byte(plain), cryptox.PKCS7())
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("plain %s: crypted %s != expect %s", plain, crypted, expect)
		}
	}
}

// go test -v -cover -run=^TestDESDecryptECB$
func TestDESDecryptECB(t *testing.T) {
	des := New([]byte("12345678"))

	cases := map[string]string{
		string([]byte{254, 185, 89, 183, 212, 100, 47, 203}):                                     "",
		string([]byte{44, 56, 133, 81, 215, 244, 137, 236}):                                      "123",
		string([]byte{109, 82, 56, 231, 116, 36, 60, 100, 116, 149, 15, 240, 198, 38, 198, 204}): "你好，世界",
	}

	for crypted, expect := range cases {
		plain, err := des.DecryptECB([]byte(crypted), cryptox.PKCS7())
		if err != nil {
			t.Error(err)
		}

		plainStr := string(plain)
		if plainStr != expect {
			t.Errorf("crypted %s: plainStr %s != expect %s", crypted, plainStr, expect)
		}
	}
}

// go test -v -cover -run=^TestDESDecryptECBHex$
func TestDESDecryptECBHex(t *testing.T) {
	des := New([]byte("12345678"))

	cases := map[string]string{
		"feb959b7d4642fcb":                 "",
		"2c388551d7f489ec":                 "123",
		"6d5238e774243c6474950ff0c626c6cc": "你好，世界",
	}

	for crypted, expect := range cases {
		plain, err := des.DecryptECBHex(crypted, cryptox.PKCS7())
		if err != nil {
			t.Error(err)
		}

		plainStr := string(plain)
		if plainStr != expect {
			t.Errorf("crypted %s: plainStr %s != expect %s", crypted, plainStr, expect)
		}
	}
}

// go test -v -cover -run=^TestDESDecryptECBBase64$
func TestDESDecryptECBBase64(t *testing.T) {
	des := New([]byte("12345678"))

	cases := map[string]string{
		"/rlZt9RkL8s=":             "",
		"LDiFUdf0iew=":             "123",
		"bVI453QkPGR0lQ/wxibGzA==": "你好，世界",
	}

	for crypted, expect := range cases {
		plain, err := des.DecryptECBBase64(crypted, cryptox.PKCS7())
		if err != nil {
			t.Error(err)
		}

		plainStr := string(plain)
		if plainStr != expect {
			t.Errorf("crypted %s: plainStr %s != expect %s", crypted, plainStr, expect)
		}
	}
}

// go test -v -cover -run=^TestDESEncryptCBC$
func TestDESEncryptCBC(t *testing.T) {
	des := New([]byte("12345678"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":      string([]byte{205, 172, 198, 131, 218, 176, 175, 188}),
		"123":   string([]byte{243, 126, 30, 174, 181, 95, 17, 128}),
		"你好，世界": string([]byte{185, 108, 29, 112, 42, 71, 169, 240, 62, 215, 156, 154, 145, 88, 110, 10}),
	}

	for plain, expect := range cases {
		crypted, err := des.EncryptCBC([]byte(plain), iv, cryptox.PKCS7())
		if err != nil {
			t.Error(err)
		}

		cryptoStr := string(crypted)
		if cryptoStr != expect {
			t.Errorf("plain %s: cryptoStr %+v != expect %+v", plain, crypted, []byte(expect))
		}
	}
}

// go test -v -cover -run=^TestDESEncryptCBCHex$
func TestDESEncryptCBCHex(t *testing.T) {
	des := New([]byte("12345678"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":      "cdacc683dab0afbc",
		"123":   "f37e1eaeb55f1180",
		"你好，世界": "b96c1d702a47a9f03ed79c9a91586e0a",
	}

	for plain, expect := range cases {
		crypted, err := des.EncryptCBCHex([]byte(plain), iv, cryptox.PKCS7())
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("plain %s: crypted %s != expect %s", plain, crypted, expect)
		}
	}
}

// go test -v -cover -run=^TestDESEncryptCBCBase64$
func TestDESEncryptCBCBase64(t *testing.T) {
	des := New([]byte("12345678"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":      "zazGg9qwr7w=",
		"123":   "834errVfEYA=",
		"你好，世界": "uWwdcCpHqfA+15yakVhuCg==",
	}

	for plain, expect := range cases {
		crypted, err := des.EncryptCBCBase64([]byte(plain), iv, cryptox.PKCS7())
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("plain %s: crypted %s != expect %s", plain, crypted, expect)
		}
	}
}

// go test -v -cover -run=^TestDESDecryptCBC$
func TestDESDecryptCBC(t *testing.T) {
	des := New([]byte("12345678"))
	iv := []byte("87654321")

	cases := map[string]string{
		string([]byte{205, 172, 198, 131, 218, 176, 175, 188}):                                   "",
		string([]byte{243, 126, 30, 174, 181, 95, 17, 128}):                                      "123",
		string([]byte{185, 108, 29, 112, 42, 71, 169, 240, 62, 215, 156, 154, 145, 88, 110, 10}): "你好，世界",
	}

	for crypted, expect := range cases {
		plain, err := des.DecryptCBC([]byte(crypted), iv, cryptox.PKCS7())
		if err != nil {
			t.Error(err)
		}

		plainStr := string(plain)
		if plainStr != expect {
			t.Errorf("crypted %s: plainStr %s != expect %s", crypted, plainStr, expect)
		}
	}
}

// go test -v -cover -run=^TestDESDecryptCBCHex$
func TestDESDecryptCBCHex(t *testing.T) {
	des := New([]byte("12345678"))
	iv := []byte("87654321")

	cases := map[string]string{
		"cdacc683dab0afbc":                 "",
		"f37e1eaeb55f1180":                 "123",
		"b96c1d702a47a9f03ed79c9a91586e0a": "你好，世界",
	}

	for crypted, expect := range cases {
		plain, err := des.DecryptCBCHex(crypted, iv, cryptox.PKCS7())
		if err != nil {
			t.Error(err)
		}

		plainStr := string(plain)
		if plainStr != expect {
			t.Errorf("crypted %s: plainStr %s != expect %s", crypted, plainStr, expect)
		}
	}
}

// go test -v -cover -run=^TestDESDecryptCBCBase64$
func TestDESDecryptCBCBase64(t *testing.T) {
	des := New([]byte("12345678"))
	iv := []byte("87654321")

	cases := map[string]string{
		"zazGg9qwr7w=":             "",
		"834errVfEYA=":             "123",
		"uWwdcCpHqfA+15yakVhuCg==": "你好，世界",
	}

	for crypted, expect := range cases {
		plain, err := des.DecryptCBCBase64(crypted, iv, cryptox.PKCS7())
		if err != nil {
			t.Error(err)
		}

		plainStr := string(plain)
		if plainStr != expect {
			t.Errorf("crypted %s: plainStr %s != expect %s", crypted, plainStr, expect)
		}
	}
}

// go test -v -cover -run=^TestDESEncryptCFB$
func TestDESEncryptCFB(t *testing.T) {
	des := New([]byte("12345678"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":      string([]byte{}),
		"123":   string([]byte{9, 102, 3}),
		"你好，世界": string([]byte{220, 233, 144, 205, 62, 200, 123, 152, 231, 237, 219, 68, 211, 43, 255}),
	}

	for plain, expect := range cases {
		crypted, err := des.EncryptCFB([]byte(plain), iv, cryptox.NoPadding())
		if err != nil {
			t.Error(err)
		}

		cryptoStr := string(crypted)
		if cryptoStr != expect {
			t.Errorf("plain %s: cryptoStr %+v != expect %+v", plain, crypted, []byte(expect))
		}
	}
}

// go test -v -cover -run=^TestDESEncryptCFBHex$
func TestDESEncryptCFBHex(t *testing.T) {
	des := New([]byte("12345678"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":      "",
		"123":   "096603",
		"你好，世界": "dce990cd3ec87b98e7eddb44d32bff",
	}

	for plain, expect := range cases {
		crypted, err := des.EncryptCFBHex([]byte(plain), iv, cryptox.NoPadding())
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("plain %s: crypted %s != expect %s", plain, crypted, expect)
		}
	}
}

// go test -v -cover -run=^TestDESEncryptCFBBase64$
func TestDESEncryptCFBBase64(t *testing.T) {
	des := New([]byte("12345678"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":      "",
		"123":   "CWYD",
		"你好，世界": "3OmQzT7Ie5jn7dtE0yv/",
	}

	for plain, expect := range cases {
		crypted, err := des.EncryptCFBBase64([]byte(plain), iv, cryptox.NoPadding())
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("plain %s: crypted %s != expect %s", plain, crypted, expect)
		}
	}
}

// go test -v -cover -run=^TestDESDecryptCFB$
func TestDESDecryptCFB(t *testing.T) {
	des := New([]byte("12345678"))
	iv := []byte("87654321")

	cases := map[string]string{
		string([]byte{}):          "",
		string([]byte{9, 102, 3}): "123",
		string([]byte{220, 233, 144, 205, 62, 200, 123, 152, 231, 237, 219, 68, 211, 43, 255}): "你好，世界",
	}

	for crypted, expect := range cases {
		plain, err := des.DecryptCFB([]byte(crypted), iv, cryptox.NoPadding())
		if err != nil {
			t.Error(err)
		}

		plainStr := string(plain)
		if plainStr != expect {
			t.Errorf("crypted %s: plainStr %s != expect %s", crypted, plainStr, expect)
		}
	}
}

// go test -v -cover -run=^TestDESDecryptCFBHex$
func TestDESDecryptCFBHex(t *testing.T) {
	des := New([]byte("12345678"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":                               "",
		"096603":                         "123",
		"dce990cd3ec87b98e7eddb44d32bff": "你好，世界",
	}

	for crypted, expect := range cases {
		plain, err := des.DecryptCFBHex(crypted, iv, cryptox.NoPadding())
		if err != nil {
			t.Error(err)
		}

		plainStr := string(plain)
		if plainStr != expect {
			t.Errorf("crypted %s: plainStr %s != expect %s", crypted, plainStr, expect)
		}
	}
}

// go test -v -cover -run=^TestDESDecryptCFBBase64$
func TestDESDecryptCFBBase64(t *testing.T) {
	des := New([]byte("12345678"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":                     "",
		"CWYD":                 "123",
		"3OmQzT7Ie5jn7dtE0yv/": "你好，世界",
	}

	for crypted, expect := range cases {
		plain, err := des.DecryptCFBBase64(crypted, iv, cryptox.NoPadding())
		if err != nil {
			t.Error(err)
		}

		plainStr := string(plain)
		if plainStr != expect {
			t.Errorf("crypted %s: plainStr %s != expect %s", crypted, plainStr, expect)
		}
	}
}

// go test -v -cover -run=^TestDESEncryptOFB$
func TestDESEncryptOFB(t *testing.T) {
	des := New([]byte("12345678"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":      string([]byte{}),
		"123":   string([]byte{9, 102, 3}),
		"你好，世界": string([]byte{220, 233, 144, 205, 62, 200, 123, 152, 169, 42, 97, 1, 193, 120, 15}),
	}

	for plain, expect := range cases {
		crypted, err := des.EncryptOFB([]byte(plain), iv, cryptox.NoPadding())
		if err != nil {
			t.Error(err)
		}

		cryptoStr := string(crypted)
		if cryptoStr != expect {
			t.Errorf("plain %s: cryptoStr %+v != expect %+v", plain, crypted, []byte(expect))
		}
	}
}

// go test -v -cover -run=^TestDESEncryptOFBHex$
func TestDESEncryptOFBHex(t *testing.T) {
	des := New([]byte("12345678"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":      "",
		"123":   "096603",
		"你好，世界": "dce990cd3ec87b98a92a6101c1780f",
	}

	for plain, expect := range cases {
		crypted, err := des.EncryptOFBHex([]byte(plain), iv, cryptox.NoPadding())
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("plain %s: crypted %s != expect %s", plain, crypted, expect)
		}
	}
}

// go test -v -cover -run=^TestDESEncryptOFBBase64$
func TestDESEncryptOFBBase64(t *testing.T) {
	des := New([]byte("12345678"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":      "",
		"123":   "CWYD",
		"你好，世界": "3OmQzT7Ie5ipKmEBwXgP",
	}

	for plain, expect := range cases {
		crypted, err := des.EncryptOFBBase64([]byte(plain), iv, cryptox.NoPadding())
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("plain %s: crypted %s != expect %s", plain, crypted, expect)
		}
	}
}

// go test -v -cover -run=^TestDESDecryptOFB$
func TestDESDecryptOFB(t *testing.T) {
	des := New([]byte("12345678"))
	iv := []byte("87654321")

	cases := map[string]string{
		string([]byte{}):          "",
		string([]byte{9, 102, 3}): "123",
		string([]byte{220, 233, 144, 205, 62, 200, 123, 152, 169, 42, 97, 1, 193, 120, 15}): "你好，世界",
	}

	for crypted, expect := range cases {
		plain, err := des.DecryptOFB([]byte(crypted), iv, cryptox.NoPadding())
		if err != nil {
			t.Error(err)
		}

		plainStr := string(plain)
		if plainStr != expect {
			t.Errorf("crypted %s: plainStr %s != expect %s", crypted, plainStr, expect)
		}
	}
}

// go test -v -cover -run=^TestDESDecryptOFBHex$
func TestDESDecryptOFBHex(t *testing.T) {
	des := New([]byte("12345678"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":                               "",
		"096603":                         "123",
		"dce990cd3ec87b98a92a6101c1780f": "你好，世界",
	}

	for crypted, expect := range cases {
		plain, err := des.DecryptOFBHex(crypted, iv, cryptox.NoPadding())
		if err != nil {
			t.Error(err)
		}

		plainStr := string(plain)
		if plainStr != expect {
			t.Errorf("crypted %s: plainStr %s != expect %s", crypted, plainStr, expect)
		}
	}
}

// go test -v -cover -run=^TestDESDecryptOFBBase64$
func TestDESDecryptOFBBase64(t *testing.T) {
	des := New([]byte("12345678"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":                     "",
		"CWYD":                 "123",
		"3OmQzT7Ie5ipKmEBwXgP": "你好，世界",
	}

	for crypted, expect := range cases {
		plain, err := des.DecryptOFBBase64(crypted, iv, cryptox.NoPadding())
		if err != nil {
			t.Error(err)
		}

		plainStr := string(plain)
		if plainStr != expect {
			t.Errorf("crypted %s: plainStr %s != expect %s", crypted, plainStr, expect)
		}
	}
}

// go test -v -cover -run=^TestDESEncryptCTR$
func TestDESEncryptCTR(t *testing.T) {
	des := New([]byte("12345678"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":      string([]byte{}),
		"123":   string([]byte{9, 102, 3}),
		"你好，世界": string([]byte{220, 233, 144, 205, 62, 200, 123, 152, 82, 201, 236, 67, 30, 240, 63}),
	}

	for plain, expect := range cases {
		crypted, err := des.EncryptCTR([]byte(plain), iv, cryptox.NoPadding())
		if err != nil {
			t.Error(err)
		}

		cryptoStr := string(crypted)
		if cryptoStr != expect {
			t.Errorf("plain %s: cryptoStr %+v != expect %+v", plain, crypted, []byte(expect))
		}
	}
}

// go test -v -cover -run=^TestDESEncryptCTRHex$
func TestDESEncryptCTRHex(t *testing.T) {
	des := New([]byte("12345678"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":      "",
		"123":   "096603",
		"你好，世界": "dce990cd3ec87b9852c9ec431ef03f",
	}

	for plain, expect := range cases {
		crypted, err := des.EncryptCTRHex([]byte(plain), iv, cryptox.NoPadding())
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("plain %s: crypted %s != expect %s", plain, crypted, expect)
		}
	}
}

// go test -v -cover -run=^TestDESEncryptCTRBase64$
func TestDESEncryptCTRBase64(t *testing.T) {
	des := New([]byte("12345678"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":      "",
		"123":   "CWYD",
		"你好，世界": "3OmQzT7Ie5hSyexDHvA/",
	}

	for plain, expect := range cases {
		crypted, err := des.EncryptCTRBase64([]byte(plain), iv, cryptox.NoPadding())
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("plain %s: crypted %s != expect %s", plain, crypted, expect)
		}
	}
}

// go test -v -cover -run=^TestDESDecryptCTR$
func TestDESDecryptCTR(t *testing.T) {
	des := New([]byte("12345678"))
	iv := []byte("87654321")

	cases := map[string]string{
		string([]byte{}):          "",
		string([]byte{9, 102, 3}): "123",
		string([]byte{220, 233, 144, 205, 62, 200, 123, 152, 82, 201, 236, 67, 30, 240, 63}): "你好，世界",
	}

	for crypted, expect := range cases {
		plain, err := des.DecryptCTR([]byte(crypted), iv, cryptox.NoPadding())
		if err != nil {
			t.Error(err)
		}

		plainStr := string(plain)
		if plainStr != expect {
			t.Errorf("crypted %s: plainStr %s != expect %s", crypted, plainStr, expect)
		}
	}
}

// go test -v -cover -run=^TestDESDecryptCTRHex$
func TestDESDecryptCTRHex(t *testing.T) {
	des := New([]byte("12345678"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":                               "",
		"096603":                         "123",
		"dce990cd3ec87b9852c9ec431ef03f": "你好，世界",
	}

	for crypted, expect := range cases {
		plain, err := des.DecryptCTRHex(crypted, iv, cryptox.NoPadding())
		if err != nil {
			t.Error(err)
		}

		plainStr := string(plain)
		if plainStr != expect {
			t.Errorf("crypted %s: plainStr %s != expect %s", crypted, plainStr, expect)
		}
	}
}

// go test -v -cover -run=^TestDESDecryptCTRBase64$
func TestDESDecryptCTRBase64(t *testing.T) {
	des := New([]byte("12345678"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":                     "",
		"CWYD":                 "123",
		"3OmQzT7Ie5hSyexDHvA/": "你好，世界",
	}

	for crypted, expect := range cases {
		plain, err := des.DecryptCTRBase64(crypted, iv, cryptox.NoPadding())
		if err != nil {
			t.Error(err)
		}

		plainStr := string(plain)
		if plainStr != expect {
			t.Errorf("crypted %s: plainStr %s != expect %s", crypted, plainStr, expect)
		}
	}
}
