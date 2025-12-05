// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package ed25519

import (
	"bytes"
	"testing"
)

type signTestCase struct {
	Data           []byte
	SignData       []byte
	SignDataHex    []byte
	SignDataBase64 []byte
}

type testRandomReader struct{}

func (testRandomReader) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = 1
	}

	return len(p), nil
}

func newTestPrivateKey() PrivateKey {
	reader := bytes.NewReader([]byte(``))

	privateKey, err := ReadPrivateKey(reader)
	if err != nil {
		panic(err)
	}

	return privateKey
}

func newTestPublicKey() PublicKey {
	reader := bytes.NewReader([]byte(``))

	publicKey, err := ReadPublicKey(reader)
	if err != nil {
		panic(err)
	}

	return publicKey
}

// go test -v -cover -run=^TestSignVerify$
func TestSignVerify(t *testing.T) {
	privateKey := newTestPrivateKey()
	publicKey := newTestPublicKey()

	testCases := []signTestCase{
		{
			Data:           []byte(""),
			SignData:       []byte(""),
			SignDataHex:    []byte(""),
			SignDataBase64: []byte(""),
		},
		{
			Data:           []byte("123"),
			SignData:       []byte(""),
			SignDataHex:    []byte(""),
			SignDataBase64: []byte(""),
		},
		{
			Data:           []byte("你好，世界"),
			SignData:       []byte(""),
			SignDataHex:    []byte(""),
			SignDataBase64: []byte(""),
		},
	}

	for _, testCase := range testCases {
		// None
		sign := privateKey.Sign(testCase.Data)

		err := publicKey.Verify(testCase.Data, sign)
		if err != nil {
			t.Fatal(err)
		}

		// Hex
		sign = privateKey.Sign(testCase.Data, WithHex())

		err = publicKey.Verify(testCase.Data, sign, WithHex())
		if err != nil {
			t.Fatal(err)
		}

		// Base64
		sign = privateKey.Sign(testCase.Data, WithBase64())

		err = publicKey.Verify(testCase.Data, sign, WithBase64())
		if err != nil {
			t.Fatal(err)
		}
	}
}
