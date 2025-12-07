// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package ed25519

import (
	"bytes"
	"slices"
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
	reader := bytes.NewReader([]byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDEyMzQ1Njc4ODc2NTQzMjExMjM0NTY3ODg3NjU0MzIx
-----END PRIVATE KEY-----`))

	privateKey, err := ReadPrivateKey(reader)
	if err != nil {
		panic(err)
	}

	return privateKey
}

func newTestPublicKey() PublicKey {
	reader := bytes.NewReader([]byte(`-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAjmI9pwiSpBdVpKQjZ+pDGbzYSx/ceC1DW45+DUzgyyM=
-----END PUBLIC KEY-----`))

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
			SignData:       []byte{151, 147, 60, 76, 20, 163, 37, 105, 38, 95, 170, 9, 135, 36, 234, 8, 193, 238, 213, 20, 68, 50, 39, 245, 4, 57, 88, 11, 36, 213, 251, 151, 99, 17, 253, 149, 187, 131, 208, 92, 161, 182, 89, 55, 79, 155, 15, 107, 105, 149, 241, 35, 56, 160, 255, 125, 233, 178, 32, 145, 205, 180, 139, 1},
			SignDataHex:    []byte("97933c4c14a32569265faa098724ea08c1eed514443227f50439580b24d5fb976311fd95bb83d05ca1b659374f9b0f6b6995f12338a0ff7de9b22091cdb48b01"),
			SignDataBase64: []byte("l5M8TBSjJWkmX6oJhyTqCMHu1RREMif1BDlYCyTV+5djEf2Vu4PQXKG2WTdPmw9raZXxIzig/33psiCRzbSLAQ=="),
		},
		{
			Data:           []byte("123"),
			SignData:       []byte{183, 71, 38, 235, 113, 179, 74, 4, 80, 180, 145, 181, 86, 153, 198, 216, 56, 131, 47, 17, 182, 193, 32, 115, 55, 234, 54, 115, 51, 233, 1, 32, 143, 47, 134, 74, 34, 230, 226, 223, 148, 144, 123, 68, 12, 216, 138, 226, 237, 65, 234, 71, 229, 183, 69, 29, 125, 144, 189, 93, 61, 220, 7, 3},
			SignDataHex:    []byte("b74726eb71b34a0450b491b55699c6d838832f11b6c1207337ea367333e901208f2f864a22e6e2df94907b440cd88ae2ed41ea47e5b7451d7d90bd5d3ddc0703"),
			SignDataBase64: []byte("t0cm63GzSgRQtJG1VpnG2DiDLxG2wSBzN+o2czPpASCPL4ZKIubi35SQe0QM2Iri7UHqR+W3RR19kL1dPdwHAw=="),
		},
		{
			Data:           []byte("你好，世界"),
			SignData:       []byte{58, 139, 184, 49, 247, 17, 190, 45, 156, 70, 236, 70, 184, 147, 248, 17, 193, 200, 151, 37, 104, 85, 120, 70, 189, 174, 24, 213, 190, 231, 23, 3, 113, 235, 186, 66, 8, 228, 77, 122, 251, 137, 161, 2, 70, 217, 98, 244, 89, 197, 53, 22, 239, 44, 219, 192, 127, 15, 40, 13, 190, 40, 99, 11},
			SignDataHex:    []byte("3a8bb831f711be2d9c46ec46b893f811c1c8972568557846bdae18d5bee7170371ebba4208e44d7afb89a10246d962f459c53516ef2cdbc07f0f280dbe28630b"),
			SignDataBase64: []byte("Oou4MfcRvi2cRuxGuJP4EcHIlyVoVXhGva4Y1b7nFwNx67pCCORNevuJoQJG2WL0WcU1Fu8s28B/DygNvihjCw=="),
		},
	}

	for _, testCase := range testCases {
		// None
		sign := privateKey.Sign(testCase.Data)

		err := publicKey.Verify(testCase.Data, sign)
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(sign, testCase.SignData) {
			t.Fatalf("data %q: got %+v != expect %+v", testCase.Data, sign, testCase.SignData)
		}

		// Hex
		sign = privateKey.Sign(testCase.Data, WithHex())

		err = publicKey.Verify(testCase.Data, sign, WithHex())
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(sign, testCase.SignDataHex) {
			t.Fatalf("data %q: got %+v != expect %+v", testCase.Data, sign, testCase.SignDataHex)
		}

		// Base64
		sign = privateKey.Sign(testCase.Data, WithBase64())

		err = publicKey.Verify(testCase.Data, sign, WithBase64())
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(sign, testCase.SignDataBase64) {
			t.Fatalf("data %q: got %+v != expect %+v", testCase.Data, sign, testCase.SignDataBase64)
		}
	}
}
