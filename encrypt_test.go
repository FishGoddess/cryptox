// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import "testing"

// go test -v -cover -run=^TestEncrypterEncrypt$
func TestEncrypterEncrypt(t *testing.T) {
	encrypter := NewEncrypter(DES, testKey, EncryptCTR, testIV, PaddingPKCS7)

	cases := map[string]string{
		"":      string([]byte{48, 92, 56, 32, 147, 125, 156, 44}),
		"123":   string([]byte{9, 102, 3, 45, 158, 112, 145, 33}),
		"你好，世界": string([]byte{220, 233, 144, 205, 62, 200, 123, 152, 82, 201, 236, 67, 30, 240, 63, 228}),
	}

	for input, expect := range cases {
		crypted, err := encrypter.Encrypt([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if string(crypted) != expect {
			t.Errorf("input %s: crypted %+v != expect %+v", input, crypted, []byte(expect))
		}
	}
}

// go test -v -cover -run=^TestEncrypterEncryptHex$
func TestEncrypterEncryptHex(t *testing.T) {
	encrypter := NewEncrypter(DES, testKey, EncryptCTR, testIV, PaddingPKCS7)

	cases := map[string]string{
		"":      "305c3820937d9c2c",
		"123":   "0966032d9e709121",
		"你好，世界": "dce990cd3ec87b9852c9ec431ef03fe4",
	}

	for input, expect := range cases {
		crypted, err := encrypter.Encrypt([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted.Hex() != expect {
			t.Errorf("input %s: crypted.Hex() %s != expect %s", input, crypted.Hex(), expect)
		}

		cryptedHex, err := encrypter.EncryptHex([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if cryptedHex != expect {
			t.Errorf("input %s: cryptedHex %s != expect %s", input, cryptedHex, expect)
		}

		if cryptedHex != crypted.Hex() {
			t.Errorf("input %s: cryptedHex %s != crypted.Base64() %s", input, cryptedHex, crypted.Hex())
		}
	}
}

// go test -v -cover -run=^TestEncrypterEncryptBase64$
func TestEncrypterEncryptBase64(t *testing.T) {
	encrypter := NewEncrypter(DES, testKey, EncryptCTR, testIV, PaddingPKCS7)

	cases := map[string]string{
		"":      "MFw4IJN9nCw=",
		"123":   "CWYDLZ5wkSE=",
		"你好，世界": "3OmQzT7Ie5hSyexDHvA/5A==",
	}

	for input, expect := range cases {
		crypted, err := encrypter.Encrypt([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if crypted.Base64() != expect {
			t.Errorf("input %s: crypted.Base64() %s != expect %s", input, crypted.Base64(), expect)
		}

		cryptedBase64, err := encrypter.EncryptBase64([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if cryptedBase64 != expect {
			t.Errorf("input %s: crypted %s != expect %s", input, cryptedBase64, expect)
		}

		if cryptedBase64 != crypted.Base64() {
			t.Errorf("input %s: cryptedBase64 %s != crypted.Base64() %s", input, cryptedBase64, crypted.Base64())
		}
	}
}
