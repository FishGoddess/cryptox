// Copyright 2023 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package aes

import (
	"testing"

	"github.com/FishGoddess/cryptox"
)

// go test -v -cover -run=^TestGenerateGCMNonce$
func TestGenerateGCMNonce(t *testing.T) {
	nonce, err := GenerateGCMNonce()
	if err != nil {
		t.Error(err)
	}

	if len(nonce) != gcmStandardNonceSize {
		t.Errorf("len(nonce) %d is wrong", len(nonce))
	}

	t.Log(nonce)
}

// go test -v -cover -run=^TestAESGCM$
func TestAESGCM(t *testing.T) {
	aes := New(testKey)

	cases := map[string]*testResult{
		"123": {
			base64String: "+YQqKJgRdgQuYdipoz5HlkO9SQ==",
		},
		"你好，世界": {
			base64String: "LAu5n5hkXgFStHCDDiM/J2LXp/OtUJsb5MWb6uzMWw==",
		},
	}

	nonce := cryptox.FromString("123456abcdef")
	for input, expect := range cases {
		crypted, err := aes.EncryptGCM(nonce, cryptox.FromString(input), nil)
		if err != nil {
			t.Error(err)
		}

		if crypted.Base64() != expect.base64String {
			t.Errorf("crypted %s is wrong", crypted.Base64())
		}

		plain, err := aes.DecryptGCM(nonce, crypted, nil)
		if err != nil {
			t.Error(err)
		}

		if string(plain) != input {
			t.Errorf("input %s: plain %+v != input %+v", input, plain, []byte(input))
		}
	}
}
