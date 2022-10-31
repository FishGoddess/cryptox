// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import (
	"crypto/cipher"
	"crypto/des"
	"testing"
)

var (
	testKey = []byte("12345678")
	testIV  = []byte("87654321")
)

func newTestBlock(t *testing.T) cipher.Block {
	block, err := des.NewCipher(testKey)
	if err != nil {
		t.Error(err)
	}

	return block
}

// go test -v -cover -run=^TestECB$
func TestECB(t *testing.T) {
	block := newTestBlock(t)

	cases := map[string]string{
		string([]byte{49, 50, 51, 52, 53, 54, 55, 56}): string([]byte{150, 208, 2, 136, 120, 213, 140, 137}),
		string([]byte{65, 66, 67, 68, 69, 70, 71, 72}): string([]byte{150, 222, 96, 62, 174, 214, 37, 111}),
	}

	for input, expect := range cases {
		plain := []byte(input)
		crypted := make([]byte, len(plain))

		err := EncryptECB(block, nil, plain, crypted)
		if err != nil {
			t.Error(err)
		}

		if string(crypted) != expect {
			t.Errorf("input %s: crypted %+v != expect %+v", input, crypted, []byte(expect))
		}

		err = DecryptECB(block, nil, crypted, plain)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("input %s: plain %+v != input %+v", input, plain, []byte(input))
		}
	}
}

// go test -v -cover -run=^TestCBC$
func TestCBC(t *testing.T) {
	block := newTestBlock(t)

	cases := map[string]string{
		string([]byte{49, 50, 51, 52, 53, 54, 55, 56}): string([]byte{133, 179, 173, 144, 63, 11, 33, 120}),
		string([]byte{65, 66, 67, 68, 69, 70, 71, 72}): string([]byte{229, 243, 175, 154, 198, 190, 13, 44}),
	}

	bs, _ := ParseBase64("hbOtkD8LIXg=")
	t.Log(bs.Bytes())

	bs, _ = ParseBase64("5fOvmsa+DSw=")
	t.Log(bs.Bytes())

	for input, expect := range cases {
		plain := []byte(input)
		crypted := make([]byte, len(plain))

		err := EncryptCBC(block, testIV, plain, crypted)
		if err != nil {
			t.Error(err)
		}

		if string(crypted) != expect {
			t.Errorf("input %s: crypted %+v != expect %+v", input, crypted, []byte(expect))
		}

		err = DecryptCBC(block, testIV, crypted, plain)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("input %s: plain %+v != input %+v", input, plain, []byte(input))
		}
	}
}

// go test -v -cover -run=^TestCFB$
func TestCFB(t *testing.T) {
	block := newTestBlock(t)

	cases := map[string]string{
		string([]byte{49, 50, 51, 52, 53, 54, 55, 56}): string([]byte{9, 102, 3, 28, 174, 67, 163, 28}),
		string([]byte{65, 66, 67, 68, 69, 70, 71, 72}): string([]byte{121, 22, 115, 108, 222, 51, 211, 108}),
	}

	for input, expect := range cases {
		plain := []byte(input)
		crypted := make([]byte, len(plain))

		err := EncryptCFB(block, testIV, plain, crypted)
		if err != nil {
			t.Error(err)
		}

		if string(crypted) != expect {
			t.Errorf("input %s: crypted %+v != expect %+v", input, crypted, []byte(expect))
		}

		err = DecryptCFB(block, testIV, crypted, plain)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("input %s: plain %+v != input %+v", input, plain, []byte(input))
		}
	}
}

// go test -v -cover -run=^TestOFB$
func TestOFB(t *testing.T) {
	block := newTestBlock(t)

	cases := map[string]string{
		string([]byte{49, 50, 51, 52, 53, 54, 55, 56}): string([]byte{9, 102, 3, 28, 174, 67, 163, 28}),
		string([]byte{65, 66, 67, 68, 69, 70, 71, 72}): string([]byte{121, 22, 115, 108, 222, 51, 211, 108}),
	}

	for input, expect := range cases {
		plain := []byte(input)
		crypted := make([]byte, len(plain))

		err := EncryptOFB(block, testIV, plain, crypted)
		if err != nil {
			t.Error(err)
		}

		if string(crypted) != expect {
			t.Errorf("input %s: crypted %+v != expect %+v", input, crypted, []byte(expect))
		}

		err = DecryptOFB(block, testIV, crypted, plain)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("input %s: plain %+v != input %+v", input, plain, []byte(input))
		}
	}
}

// go test -v -cover -run=^TestCTR$
func TestCTR(t *testing.T) {
	block := newTestBlock(t)

	cases := map[string]string{
		string([]byte{49, 50, 51, 52, 53, 54, 55, 56}): string([]byte{9, 102, 3, 28, 174, 67, 163, 28}),
		string([]byte{65, 66, 67, 68, 69, 70, 71, 72}): string([]byte{121, 22, 115, 108, 222, 51, 211, 108}),
	}

	for input, expect := range cases {
		plain := []byte(input)
		crypted := make([]byte, len(plain))

		err := EncryptCTR(block, testIV, plain, crypted)
		if err != nil {
			t.Error(err)
		}

		if string(crypted) != expect {
			t.Errorf("input %s: crypted %+v != expect %+v", input, crypted, []byte(expect))
		}

		err = DecryptCTR(block, testIV, crypted, plain)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("input %s: plain %+v != input %+v", input, plain, []byte(input))
		}
	}
}
