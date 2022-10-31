// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import "testing"

// go test -v -cover -run=^TestDecrypterDecrypt$
func TestDecrypterDecrypt(t *testing.T) {
	decrypter := NewDecrypter(DES, testKey, DecryptCTR, testIV, UnPaddingPKCS7)

	cases := map[string]string{
		string([]byte{48, 92, 56, 32, 147, 125, 156, 44}):                                         "",
		string([]byte{9, 102, 3, 45, 158, 112, 145, 33}):                                          "123",
		string([]byte{220, 233, 144, 205, 62, 200, 123, 152, 82, 201, 236, 67, 30, 240, 63, 228}): "你好，世界",
	}

	for input, expect := range cases {
		plain, err := decrypter.Decrypt([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if plain.String() != expect {
			t.Errorf("input %s: plain %s != expect %s", input, plain, expect)
		}
	}
}

// go test -v -cover -run=^TestDecrypterDecryptHex$
func TestDecrypterDecryptHex(t *testing.T) {
	decrypter := NewDecrypter(DES, testKey, DecryptCTR, testIV, UnPaddingPKCS7)

	cases := map[string]string{
		"305c3820937d9c2c":                 "",
		"0966032d9e709121":                 "123",
		"dce990cd3ec87b9852c9ec431ef03fe4": "你好，世界",
	}

	for input, expect := range cases {
		plain, err := decrypter.DecryptHex(input)
		if err != nil {
			t.Error(err)
		}

		if plain.String() != expect {
			t.Errorf("input %s: plain %s != expect %s", input, plain, expect)
		}
	}
}

// go test -v -cover -run=^TestDecrypterDecryptBase64$
func TestDecrypterDecryptBase64(t *testing.T) {
	decrypter := NewDecrypter(DES, testKey, DecryptCTR, testIV, UnPaddingPKCS7)

	cases := map[string]string{
		"MFw4IJN9nCw=":             "",
		"CWYDLZ5wkSE=":             "123",
		"3OmQzT7Ie5hSyexDHvA/5A==": "你好，世界",
	}

	for input, expect := range cases {
		plain, err := decrypter.DecryptBase64(input)
		if err != nil {
			t.Error(err)
		}

		if plain.String() != expect {
			t.Errorf("input %s: plain %s != expect %s", input, plain, expect)
		}
	}
}
