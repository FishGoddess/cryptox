// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package des

import (
	"testing"

	"github.com/FishGoddess/cryptox"
)

// go test -v -cover -run=^TestTripleEncryptECB$
func TestTripleEncryptECB(t *testing.T) {
	des := NewTriple([]byte("12345678ABCDEFGH87654321"))

	cases := map[string]string{
		"":      string([]byte{73, 245, 96, 2, 192, 105, 51, 72}),
		"123":   string([]byte{37, 137, 202, 82, 231, 19, 57, 53}),
		"你好，世界": string([]byte{212, 119, 38, 169, 194, 81, 104, 5, 1, 74, 9, 70, 20, 45, 187, 182}),
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

// go test -v -cover -run=^TestTripleEncryptECBHex$
func TestTripleEncryptECBHex(t *testing.T) {
	des := NewTriple([]byte("12345678ABCDEFGH87654321"))

	cases := map[string]string{
		"":      "49f56002c0693348",
		"123":   "2589ca52e7133935",
		"你好，世界": "d47726a9c2516805014a0946142dbbb6",
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

// go test -v -cover -run=^TestTripleEncryptECBBase64$
func TestTripleEncryptECBBase64(t *testing.T) {
	des := NewTriple([]byte("12345678ABCDEFGH87654321"))

	cases := map[string]string{
		"":      "SfVgAsBpM0g=",
		"123":   "JYnKUucTOTU=",
		"你好，世界": "1HcmqcJRaAUBSglGFC27tg==",
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

// go test -v -cover -run=^TestTripleDecryptECB$
func TestTripleDecryptECB(t *testing.T) {
	des := NewTriple([]byte("12345678ABCDEFGH87654321"))

	cases := map[string]string{
		string([]byte{73, 245, 96, 2, 192, 105, 51, 72}):                                   "",
		string([]byte{37, 137, 202, 82, 231, 19, 57, 53}):                                  "123",
		string([]byte{212, 119, 38, 169, 194, 81, 104, 5, 1, 74, 9, 70, 20, 45, 187, 182}): "你好，世界",
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

// go test -v -cover -run=^TestTripleDecryptECBHex$
func TestTripleDecryptECBHex(t *testing.T) {
	des := NewTriple([]byte("12345678ABCDEFGH87654321"))

	cases := map[string]string{
		"49f56002c0693348":                 "",
		"2589ca52e7133935":                 "123",
		"d47726a9c2516805014a0946142dbbb6": "你好，世界",
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

// go test -v -cover -run=^TestTripleDecryptECBBase64$
func TestTripleDecryptECBBase64(t *testing.T) {
	des := NewTriple([]byte("12345678ABCDEFGH87654321"))

	cases := map[string]string{
		"SfVgAsBpM0g=":             "",
		"JYnKUucTOTU=":             "123",
		"1HcmqcJRaAUBSglGFC27tg==": "你好，世界",
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

// go test -v -cover -run=^TestTripleEncryptCBC$
func TestTripleEncryptCBC(t *testing.T) {
	des := NewTriple([]byte("12345678ABCDEFGH87654321"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":      string([]byte{70, 170, 202, 51, 163, 225, 197, 228}),
		"123":   string([]byte{81, 238, 137, 172, 209, 239, 198, 42}),
		"你好，世界": string([]byte{232, 31, 15, 88, 209, 165, 0, 7, 119, 65, 204, 53, 39, 116, 226, 80}),
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

// go test -v -cover -run=^TestTripleEncryptCBCHex$
func TestTripleEncryptCBCHex(t *testing.T) {
	des := NewTriple([]byte("12345678ABCDEFGH87654321"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":      "46aaca33a3e1c5e4",
		"123":   "51ee89acd1efc62a",
		"你好，世界": "e81f0f58d1a500077741cc352774e250",
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

// go test -v -cover -run=^TestTripleEncryptCBCBase64$
func TestTripleEncryptCBCBase64(t *testing.T) {
	des := NewTriple([]byte("12345678ABCDEFGH87654321"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":      "RqrKM6PhxeQ=",
		"123":   "Ue6JrNHvxio=",
		"你好，世界": "6B8PWNGlAAd3Qcw1J3TiUA==",
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

// go test -v -cover -run=^TestTripleDecryptCBC$
func TestTripleDecryptCBC(t *testing.T) {
	des := NewTriple([]byte("12345678ABCDEFGH87654321"))
	iv := []byte("87654321")

	cases := map[string]string{
		string([]byte{70, 170, 202, 51, 163, 225, 197, 228}):                                "",
		string([]byte{81, 238, 137, 172, 209, 239, 198, 42}):                                "123",
		string([]byte{232, 31, 15, 88, 209, 165, 0, 7, 119, 65, 204, 53, 39, 116, 226, 80}): "你好，世界",
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

// go test -v -cover -run=^TestTripleDecryptCBCHex$
func TestTripleDecryptCBCHex(t *testing.T) {
	des := NewTriple([]byte("12345678ABCDEFGH87654321"))
	iv := []byte("87654321")

	cases := map[string]string{
		"46aaca33a3e1c5e4":                 "",
		"51ee89acd1efc62a":                 "123",
		"e81f0f58d1a500077741cc352774e250": "你好，世界",
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

// go test -v -cover -run=^TestTripleDecryptCBCBase64$
func TestTripleDecryptCBCBase64(t *testing.T) {
	des := NewTriple([]byte("12345678ABCDEFGH87654321"))
	iv := []byte("87654321")

	cases := map[string]string{
		"RqrKM6PhxeQ=":             "",
		"Ue6JrNHvxio=":             "123",
		"6B8PWNGlAAd3Qcw1J3TiUA==": "你好，世界",
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

// go test -v -cover -run=^TestTripleEncryptCFB$
func TestTripleEncryptCFB(t *testing.T) {
	des := NewTriple([]byte("12345678ABCDEFGH87654321"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":      string([]byte{}),
		"123":   string([]byte{210, 71, 136}),
		"你好，世界": string([]byte{7, 200, 27, 33, 117, 119, 69, 251, 214, 81, 119, 34, 242, 142, 227}),
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

// go test -v -cover -run=^TestTripleEncryptCFBHex$
func TestTripleEncryptCFBHex(t *testing.T) {
	des := NewTriple([]byte("12345678ABCDEFGH87654321"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":      "",
		"123":   "d24788",
		"你好，世界": "07c81b21757745fbd6517722f28ee3",
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

// go test -v -cover -run=^TestTripleEncryptCFBBase64$
func TestTripleEncryptCFBBase64(t *testing.T) {
	des := NewTriple([]byte("12345678ABCDEFGH87654321"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":      "",
		"123":   "0keI",
		"你好，世界": "B8gbIXV3RfvWUXci8o7j",
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

// go test -v -cover -run=^TestTripleDecryptCFB$
func TestTripleDecryptCFB(t *testing.T) {
	des := NewTriple([]byte("12345678ABCDEFGH87654321"))
	iv := []byte("87654321")

	cases := map[string]string{
		string([]byte{}):             "",
		string([]byte{210, 71, 136}): "123",
		string([]byte{7, 200, 27, 33, 117, 119, 69, 251, 214, 81, 119, 34, 242, 142, 227}): "你好，世界",
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

// go test -v -cover -run=^TestTripleDecryptCFBHex$
func TestTripleDecryptCFBHex(t *testing.T) {
	des := NewTriple([]byte("12345678ABCDEFGH87654321"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":                               "",
		"d24788":                         "123",
		"07c81b21757745fbd6517722f28ee3": "你好，世界",
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

// go test -v -cover -run=^TestTripleDecryptCFBBase64$
func TestTripleDecryptCFBBase64(t *testing.T) {
	des := NewTriple([]byte("12345678ABCDEFGH87654321"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":                     "",
		"0keI":                 "123",
		"B8gbIXV3RfvWUXci8o7j": "你好，世界",
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

// go test -v -cover -run=^TestTripleEncryptOFB$
func TestTripleEncryptOFB(t *testing.T) {
	des := NewTriple([]byte("12345678ABCDEFGH87654321"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":      string([]byte{}),
		"123":   string([]byte{210, 71, 136}),
		"你好，世界": string([]byte{7, 200, 27, 33, 117, 119, 69, 251, 78, 85, 83, 153, 35, 11, 99}),
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

// go test -v -cover -run=^TestTripleEncryptOFBHex$
func TestTripleEncryptOFBHex(t *testing.T) {
	des := NewTriple([]byte("12345678ABCDEFGH87654321"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":      "",
		"123":   "d24788",
		"你好，世界": "07c81b21757745fb4e555399230b63",
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

// go test -v -cover -run=^TestTripleEncryptOFBBase64$
func TestTripleEncryptOFBBase64(t *testing.T) {
	des := NewTriple([]byte("12345678ABCDEFGH87654321"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":      "",
		"123":   "0keI",
		"你好，世界": "B8gbIXV3RftOVVOZIwtj",
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

// go test -v -cover -run=^TestTripleDecryptOFB$
func TestTripleDecryptOFB(t *testing.T) {
	des := NewTriple([]byte("12345678ABCDEFGH87654321"))
	iv := []byte("87654321")

	cases := map[string]string{
		string([]byte{}):             "",
		string([]byte{210, 71, 136}): "123",
		string([]byte{7, 200, 27, 33, 117, 119, 69, 251, 78, 85, 83, 153, 35, 11, 99}): "你好，世界",
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

// go test -v -cover -run=^TestTripleDecryptOFBHex$
func TestTripleDecryptOFBHex(t *testing.T) {
	des := NewTriple([]byte("12345678ABCDEFGH87654321"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":                               "",
		"d24788":                         "123",
		"07c81b21757745fb4e555399230b63": "你好，世界",
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

// go test -v -cover -run=^TestTripleDecryptOFBBase64$
func TestTripleDecryptOFBBase64(t *testing.T) {
	des := NewTriple([]byte("12345678ABCDEFGH87654321"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":                     "",
		"0keI":                 "123",
		"B8gbIXV3RftOVVOZIwtj": "你好，世界",
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

// go test -v -cover -run=^TestTripleEncryptCTR$
func TestTripleEncryptCTR(t *testing.T) {
	des := NewTriple([]byte("12345678ABCDEFGH87654321"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":      string([]byte{}),
		"123":   string([]byte{210, 71, 136}),
		"你好，世界": string([]byte{7, 200, 27, 33, 117, 119, 69, 251, 24, 219, 209, 174, 15, 129, 116}),
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

// go test -v -cover -run=^TestTripleEncryptCTRHex$
func TestTripleEncryptCTRHex(t *testing.T) {
	des := NewTriple([]byte("12345678ABCDEFGH87654321"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":      "",
		"123":   "d24788",
		"你好，世界": "07c81b21757745fb18dbd1ae0f8174",
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

// go test -v -cover -run=^TestTripleEncryptCTRBase64$
func TestTripleEncryptCTRBase64(t *testing.T) {
	des := NewTriple([]byte("12345678ABCDEFGH87654321"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":      "",
		"123":   "0keI",
		"你好，世界": "B8gbIXV3RfsY29GuD4F0",
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

// go test -v -cover -run=^TestTripleDecryptCTR$
func TestTripleDecryptCTR(t *testing.T) {
	des := NewTriple([]byte("12345678ABCDEFGH87654321"))
	iv := []byte("87654321")

	cases := map[string]string{
		string([]byte{}):             "",
		string([]byte{210, 71, 136}): "123",
		string([]byte{7, 200, 27, 33, 117, 119, 69, 251, 24, 219, 209, 174, 15, 129, 116}): "你好，世界",
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

// go test -v -cover -run=^TestTripleDecryptCTRHex$
func TestTripleDecryptCTRHex(t *testing.T) {
	des := NewTriple([]byte("12345678ABCDEFGH87654321"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":                               "",
		"d24788":                         "123",
		"07c81b21757745fb18dbd1ae0f8174": "你好，世界",
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

// go test -v -cover -run=^TestTripleDecryptCTRBase64$
func TestTripleDecryptCTRBase64(t *testing.T) {
	des := NewTriple([]byte("12345678ABCDEFGH87654321"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":                     "",
		"0keI":                 "123",
		"B8gbIXV3RfsY29GuD4F0": "你好，世界",
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
