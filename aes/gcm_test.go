// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package aes

import (
	"testing"
)

// go test -v -cover -count=1 -test.cpu=1 -run=^TestGenerateGCMNonce$
func TestGenerateGCMNonce(t *testing.T) {
	nonce, err := GenerateGCMNonce()
	if err != nil {
		t.Fatal(err)
	}

	if len(nonce) != gcmStandardNonceSize {
		t.Fatalf("len(nonce) %d is wrong", len(nonce))
	}

	t.Log(nonce)
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestAESGCM$
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

	nonce := []byte("123456abcdef")
	for input, expect := range cases {
		crypted, err := aes.EncryptGCM(nonce, []byte(input), nil)
		if err != nil {
			t.Fatal(err)
		}

		if crypted.Base64() != expect.base64String {
			t.Fatalf("crypted %s is wrong", crypted.Base64())
		}

		plain, err := aes.DecryptGCM(nonce, crypted, nil)
		if err != nil {
			t.Fatal(err)
		}

		if string(plain) != input {
			t.Fatalf("input %s: plain %+v != input %+v", input, plain, []byte(input))
		}
	}
}
