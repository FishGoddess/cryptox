// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package des

import (
	"testing"

	"github.com/FishGoddess/cryptox"
)

// go test -v -cover -run=^TestAESEncryptECB$
func TestAESEncryptECB(t *testing.T) {
	des := New([]byte("12345678876543211234567887654321"))

	cases := map[string]string{
		"":      string([]byte{46, 71, 207, 219, 18, 238, 77, 216, 177, 177, 186, 232, 19, 197, 96, 172}),
		"123":   string([]byte{173, 62, 123, 195, 111, 6, 34, 76, 86, 148, 68, 12, 179, 251, 241, 79}),
		"你好，世界": string([]byte{219, 84, 167, 180, 5, 230, 163, 133, 6, 168, 131, 20, 69, 151, 26, 163}),
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

// go test -v -cover -run=^TestAESEncryptECBHex$
func TestAESEncryptECBHex(t *testing.T) {
	des := New([]byte("12345678876543211234567887654321"))

	cases := map[string]string{
		"":      "2e47cfdb12ee4dd8b1b1bae813c560ac",
		"123":   "ad3e7bc36f06224c5694440cb3fbf14f",
		"你好，世界": "db54a7b405e6a38506a8831445971aa3",
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

// go test -v -cover -run=^TestAESEncryptECBBase64$
func TestAESEncryptECBBase64(t *testing.T) {
	des := New([]byte("12345678876543211234567887654321"))

	cases := map[string]string{
		"":      "LkfP2xLuTdixsbroE8VgrA==",
		"123":   "rT57w28GIkxWlEQMs/vxTw==",
		"你好，世界": "21SntAXmo4UGqIMURZcaow==",
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

// go test -v -cover -run=^TestAESDecryptECB$
func TestAESDecryptECB(t *testing.T) {
	des := New([]byte("12345678876543211234567887654321"))

	cases := map[string]string{
		string([]byte{46, 71, 207, 219, 18, 238, 77, 216, 177, 177, 186, 232, 19, 197, 96, 172}): "",
		string([]byte{173, 62, 123, 195, 111, 6, 34, 76, 86, 148, 68, 12, 179, 251, 241, 79}):    "123",
		string([]byte{219, 84, 167, 180, 5, 230, 163, 133, 6, 168, 131, 20, 69, 151, 26, 163}):   "你好，世界",
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

// go test -v -cover -run=^TestAESDecryptECBHex$
func TestAESDecryptECBHex(t *testing.T) {
	des := New([]byte("12345678876543211234567887654321"))

	cases := map[string]string{
		"2e47cfdb12ee4dd8b1b1bae813c560ac": "",
		"ad3e7bc36f06224c5694440cb3fbf14f": "123",
		"db54a7b405e6a38506a8831445971aa3": "你好，世界",
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

// go test -v -cover -run=^TestAESDecryptECBBase64$
func TestAESDecryptECBBase64(t *testing.T) {
	des := New([]byte("12345678876543211234567887654321"))

	cases := map[string]string{
		"LkfP2xLuTdixsbroE8VgrA==": "",
		"rT57w28GIkxWlEQMs/vxTw==": "123",
		"21SntAXmo4UGqIMURZcaow==": "你好，世界",
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

// go test -v -cover -run=^TestAESEncryptCBC$
func TestAESEncryptCBC(t *testing.T) {
	des := New([]byte("12345678876543211234567887654321"))
	iv := []byte("8765432112345678")

	cases := map[string]string{
		"":      string([]byte{204, 67, 101, 243, 145, 108, 173, 196, 169, 232, 196, 238, 119, 228, 54, 135}),
		"123":   string([]byte{75, 118, 159, 30, 23, 149, 246, 32, 15, 157, 198, 43, 188, 232, 232, 176}),
		"你好，世界": string([]byte{102, 137, 142, 49, 76, 207, 80, 189, 78, 85, 77, 31, 166, 172, 180, 144}),
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

// go test -v -cover -run=^TestAESEncryptCBCHex$
func TestAESEncryptCBCHex(t *testing.T) {
	des := New([]byte("12345678876543211234567887654321"))
	iv := []byte("8765432112345678")

	cases := map[string]string{
		"":      "cc4365f3916cadc4a9e8c4ee77e43687",
		"123":   "4b769f1e1795f6200f9dc62bbce8e8b0",
		"你好，世界": "66898e314ccf50bd4e554d1fa6acb490",
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

// go test -v -cover -run=^TestAESEncryptCBCBase64$
func TestAESEncryptCBCBase64(t *testing.T) {
	des := New([]byte("12345678876543211234567887654321"))
	iv := []byte("8765432112345678")

	cases := map[string]string{
		"":      "zENl85FsrcSp6MTud+Q2hw==",
		"123":   "S3afHheV9iAPncYrvOjosA==",
		"你好，世界": "ZomOMUzPUL1OVU0fpqy0kA==",
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

// go test -v -cover -run=^TestAESDecryptCBC$
func TestAESDecryptCBC(t *testing.T) {
	des := New([]byte("12345678876543211234567887654321"))
	iv := []byte("8765432112345678")

	cases := map[string]string{
		string([]byte{204, 67, 101, 243, 145, 108, 173, 196, 169, 232, 196, 238, 119, 228, 54, 135}): "",
		string([]byte{75, 118, 159, 30, 23, 149, 246, 32, 15, 157, 198, 43, 188, 232, 232, 176}):     "123",
		string([]byte{102, 137, 142, 49, 76, 207, 80, 189, 78, 85, 77, 31, 166, 172, 180, 144}):      "你好，世界",
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

// go test -v -cover -run=^TestAESDecryptCBCHex$
func TestAESDecryptCBCHex(t *testing.T) {
	des := New([]byte("12345678876543211234567887654321"))
	iv := []byte("8765432112345678")

	cases := map[string]string{
		"cc4365f3916cadc4a9e8c4ee77e43687": "",
		"4b769f1e1795f6200f9dc62bbce8e8b0": "123",
		"66898e314ccf50bd4e554d1fa6acb490": "你好，世界",
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

// go test -v -cover -run=^TestAESDecryptCBCBase64$
func TestAESDecryptCBCBase64(t *testing.T) {
	des := New([]byte("12345678876543211234567887654321"))
	iv := []byte("8765432112345678")

	cases := map[string]string{
		"zENl85FsrcSp6MTud+Q2hw==": "",
		"S3afHheV9iAPncYrvOjosA==": "123",
		"ZomOMUzPUL1OVU0fpqy0kA==": "你好，世界",
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

// go test -v -cover -run=^TestAESEncryptCFB$
func TestAESEncryptCFB(t *testing.T) {
	des := New([]byte("12345678876543211234567887654321"))
	iv := []byte("8765432112345678")

	cases := map[string]string{
		"":      string([]byte{}),
		"123":   string([]byte{108, 145, 37}),
		"你好，世界": string([]byte{185, 30, 182, 141, 214, 82, 9, 57, 81, 9, 57, 101, 242, 49, 117}),
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

// go test -v -cover -run=^TestAESEncryptCFBHex$
func TestAESEncryptCFBHex(t *testing.T) {
	des := New([]byte("12345678876543211234567887654321"))
	iv := []byte("8765432112345678")

	cases := map[string]string{
		"":      "",
		"123":   "6c9125",
		"你好，世界": "b91eb68dd652093951093965f23175",
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

// go test -v -cover -run=^TestAESEncryptCFBBase64$
func TestAESEncryptCFBBase64(t *testing.T) {
	des := New([]byte("12345678876543211234567887654321"))
	iv := []byte("8765432112345678")

	cases := map[string]string{
		"":      "",
		"123":   "bJEl",
		"你好，世界": "uR62jdZSCTlRCTll8jF1",
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

// go test -v -cover -run=^TestAESDecryptCFB$
func TestAESDecryptCFB(t *testing.T) {
	des := New([]byte("12345678876543211234567887654321"))
	iv := []byte("8765432112345678")

	cases := map[string]string{
		string([]byte{}):             "",
		string([]byte{108, 145, 37}): "123",
		string([]byte{185, 30, 182, 141, 214, 82, 9, 57, 81, 9, 57, 101, 242, 49, 117}): "你好，世界",
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

// go test -v -cover -run=^TestAESDecryptCFBHex$
func TestAESDecryptCFBHex(t *testing.T) {
	des := New([]byte("12345678876543211234567887654321"))
	iv := []byte("8765432112345678")

	cases := map[string]string{
		"":                               "",
		"6c9125":                         "123",
		"b91eb68dd652093951093965f23175": "你好，世界",
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

// go test -v -cover -run=^TestAESDecryptCFBBase64$
func TestAESDecryptCFBBase64(t *testing.T) {
	des := New([]byte("12345678876543211234567887654321"))
	iv := []byte("8765432112345678")

	cases := map[string]string{
		"":                     "",
		"bJEl":                 "123",
		"uR62jdZSCTlRCTll8jF1": "你好，世界",
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

// go test -v -cover -run=^TestAESEncryptOFB$
func TestAESEncryptOFB(t *testing.T) {
	des := New([]byte("12345678876543211234567887654321"))
	iv := []byte("8765432112345678")

	cases := map[string]string{
		"":      string([]byte{}),
		"123":   string([]byte{108, 145, 37}),
		"你好，世界": string([]byte{185, 30, 182, 141, 214, 82, 9, 57, 81, 9, 57, 101, 242, 49, 117}),
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

// go test -v -cover -run=^TestAESEncryptOFBHex$
func TestAESEncryptOFBHex(t *testing.T) {
	des := New([]byte("12345678876543211234567887654321"))
	iv := []byte("8765432112345678")

	cases := map[string]string{
		"":      "",
		"123":   "6c9125",
		"你好，世界": "b91eb68dd652093951093965f23175",
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

// go test -v -cover -run=^TestAESEncryptOFBBase64$
func TestAESEncryptOFBBase64(t *testing.T) {
	des := New([]byte("12345678876543211234567887654321"))
	iv := []byte("8765432112345678")

	cases := map[string]string{
		"":      "",
		"123":   "bJEl",
		"你好，世界": "uR62jdZSCTlRCTll8jF1",
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

// go test -v -cover -run=^TestAESDecryptOFB$
func TestAESDecryptOFB(t *testing.T) {
	des := New([]byte("12345678876543211234567887654321"))
	iv := []byte("8765432112345678")

	cases := map[string]string{
		string([]byte{}):             "",
		string([]byte{108, 145, 37}): "123",
		string([]byte{185, 30, 182, 141, 214, 82, 9, 57, 81, 9, 57, 101, 242, 49, 117}): "你好，世界",
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

// go test -v -cover -run=^TestAESDecryptOFBHex$
func TestAESDecryptOFBHex(t *testing.T) {
	des := New([]byte("12345678876543211234567887654321"))
	iv := []byte("8765432112345678")

	cases := map[string]string{
		"":                               "",
		"6c9125":                         "123",
		"b91eb68dd652093951093965f23175": "你好，世界",
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

// go test -v -cover -run=^TestAESDecryptOFBBase64$
func TestAESDecryptOFBBase64(t *testing.T) {
	des := New([]byte("12345678876543211234567887654321"))
	iv := []byte("8765432112345678")

	cases := map[string]string{
		"":                     "",
		"bJEl":                 "123",
		"uR62jdZSCTlRCTll8jF1": "你好，世界",
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

// go test -v -cover -run=^TestAESEncryptCTR$
func TestAESEncryptCTR(t *testing.T) {
	des := New([]byte("12345678876543211234567887654321"))
	iv := []byte("8765432112345678")

	cases := map[string]string{
		"":      string([]byte{}),
		"123":   string([]byte{108, 145, 37}),
		"你好，世界": string([]byte{185, 30, 182, 141, 214, 82, 9, 57, 81, 9, 57, 101, 242, 49, 117}),
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

// go test -v -cover -run=^TestAESEncryptCTRHex$
func TestAESEncryptCTRHex(t *testing.T) {
	des := New([]byte("12345678876543211234567887654321"))
	iv := []byte("8765432112345678")

	cases := map[string]string{
		"":      "",
		"123":   "6c9125",
		"你好，世界": "b91eb68dd652093951093965f23175",
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

// go test -v -cover -run=^TestAESEncryptCTRBase64$
func TestAESEncryptCTRBase64(t *testing.T) {
	des := New([]byte("12345678876543211234567887654321"))
	iv := []byte("8765432112345678")

	cases := map[string]string{
		"":      "",
		"123":   "bJEl",
		"你好，世界": "uR62jdZSCTlRCTll8jF1",
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

// go test -v -cover -run=^TestAESDecryptCTR$
func TestAESDecryptCTR(t *testing.T) {
	des := New([]byte("12345678876543211234567887654321"))
	iv := []byte("8765432112345678")

	cases := map[string]string{
		string([]byte{}):             "",
		string([]byte{108, 145, 37}): "123",
		string([]byte{185, 30, 182, 141, 214, 82, 9, 57, 81, 9, 57, 101, 242, 49, 117}): "你好，世界",
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

// go test -v -cover -run=^TestAESDecryptCTRHex$
func TestAESDecryptCTRHex(t *testing.T) {
	des := New([]byte("12345678876543211234567887654321"))
	iv := []byte("8765432112345678")

	cases := map[string]string{
		"":                               "",
		"6c9125":                         "123",
		"b91eb68dd652093951093965f23175": "你好，世界",
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

// go test -v -cover -run=^TestAESDecryptCTRBase64$
func TestAESDecryptCTRBase64(t *testing.T) {
	des := New([]byte("12345678876543211234567887654321"))
	iv := []byte("8765432112345678")

	cases := map[string]string{
		"":                     "",
		"bJEl":                 "123",
		"uR62jdZSCTlRCTll8jF1": "你好，世界",
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
