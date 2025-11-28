// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package des

import (
	"crypto/des"
	"testing"

	"github.com/FishGoddess/cryptox/bytes/encoding"
	"github.com/FishGoddess/cryptox/bytes/padding"
)

var (
	testTripleKey = []byte("123456788765432112345678")
)

// go test -v -cover -run=^TestNewTripleBlock$
func TestNewTripleBlock(t *testing.T) {
	block, blockSize, err := newTripleBlock(testTripleKey)
	if err != nil {
		t.Fatal(err)
	}

	if block == nil {
		t.Fatal("block == nil")
	}

	if blockSize != block.BlockSize() {
		t.Fatalf("blockSize %d != block.BlockSize() %d", blockSize, block.BlockSize())
	}

	wantBlock, err := des.NewTripleDESCipher(testTripleKey)
	if err != nil {
		t.Fatal(err)
	}

	if blockSize != wantBlock.BlockSize() {
		t.Fatalf("blockSize %d != wantBlock.BlockSize() %d", blockSize, wantBlock.BlockSize())
	}
}

// go test -v -cover -run=^TestTripleECB$
func TestTripleECB(t *testing.T) {
	testCases := []testCase{
		{
			Data:              []byte(""),
			EncryptData:       []byte{163, 133, 24, 236, 31, 63, 147, 38},
			EncryptDataHex:    []byte("a38518ec1f3f9326"),
			EncryptDataBase64: []byte("o4UY7B8/kyY="),
		},
		{
			Data:              []byte("123"),
			EncryptData:       []byte{185, 2, 158, 11, 229, 10, 126, 217},
			EncryptDataHex:    []byte("b9029e0be50a7ed9"),
			EncryptDataBase64: []byte("uQKeC+UKftk="),
		},
		{
			Data:              []byte("你好，世界"),
			EncryptData:       []byte{224, 251, 123, 121, 70, 219, 201, 188, 14, 248, 74, 206, 42, 34, 16, 102},
			EncryptDataHex:    []byte("e0fb7b7946dbc9bc0ef84ace2a221066"),
			EncryptDataBase64: []byte("4Pt7eUbbybwO+ErOKiIQZg=="),
		},
	}

	encrypt := func(data []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
		return EncryptTripleECB(data, testTripleKey, padding, encoding)
	}

	decrypt := func(data []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
		return DecryptTripleECB(data, testTripleKey, padding, encoding)
	}

	if err := testEncryptAndDecrypt(t.Name(), encrypt, decrypt, testCases); err != nil {
		t.Fatal(err)
	}
}

// go test -v -cover -run=^TestTripleCBC$
func TestTripleCBC(t *testing.T) {
	testCases := []testCase{
		{
			Data:              []byte(""),
			EncryptData:       []byte{39, 65, 204, 186, 76, 78, 149, 112},
			EncryptDataHex:    []byte("2741ccba4c4e9570"),
			EncryptDataBase64: []byte("J0HMukxOlXA="),
		},
		{
			Data:              []byte("123"),
			EncryptData:       []byte{0, 247, 123, 125, 239, 59, 132, 68},
			EncryptDataHex:    []byte("00f77b7def3b8444"),
			EncryptDataBase64: []byte("APd7fe87hEQ="),
		},
		{
			Data:              []byte("你好，世界"),
			EncryptData:       []byte{153, 124, 242, 118, 122, 226, 179, 98, 152, 158, 80, 119, 178, 247, 19, 62},
			EncryptDataHex:    []byte("997cf2767ae2b362989e5077b2f7133e"),
			EncryptDataBase64: []byte("mXzydnris2KYnlB3svcTPg=="),
		},
	}

	encrypt := func(data []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
		return EncryptTripleCBC(data, testTripleKey, testIV, padding, encoding)
	}

	decrypt := func(data []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
		return DecryptTripleCBC(data, testTripleKey, testIV, padding, encoding)
	}

	if err := testEncryptAndDecrypt(t.Name(), encrypt, decrypt, testCases); err != nil {
		t.Fatal(err)
	}
}

// go test -v -cover -run=^TestTripleCFB$
func TestTripleCFB(t *testing.T) {
	testCases := []testCase{
		{
			Data:              []byte(""),
			EncryptData:       []byte{92, 169, 236, 137, 11, 246, 123, 32},
			EncryptDataHex:    []byte("5ca9ec890bf67b20"),
			EncryptDataBase64: []byte("XKnsiQv2eyA="),
		},
		{
			Data:              []byte("123"),
			EncryptData:       []byte{101, 147, 215, 132, 6, 251, 118, 45},
			EncryptDataHex:    []byte("6593d78406fb762d"),
			EncryptDataBase64: []byte("ZZPXhAb7di0="),
		},
		{
			Data:              []byte("你好，世界"),
			EncryptData:       []byte{176, 28, 68, 100, 166, 67, 156, 148, 85, 69, 217, 58, 184, 136, 197, 51},
			EncryptDataHex:    []byte("b01c4464a6439c945545d93ab888c533"),
			EncryptDataBase64: []byte("sBxEZKZDnJRVRdk6uIjFMw=="),
		},
	}

	encrypt := func(data []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
		return EncryptTripleCFB(data, testTripleKey, testIV, padding, encoding)
	}

	decrypt := func(data []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
		return DecryptTripleCFB(data, testTripleKey, testIV, padding, encoding)
	}

	if err := testEncryptAndDecrypt(t.Name(), encrypt, decrypt, testCases); err != nil {
		t.Fatal(err)
	}
}

// go test -v -cover -run=^TestTripleOFB$
func TestTripleOFB(t *testing.T) {
	testCases := []testCase{
		{
			Data:              []byte(""),
			EncryptData:       []byte{92, 169, 236, 137, 11, 246, 123, 32},
			EncryptDataHex:    []byte("5ca9ec890bf67b20"),
			EncryptDataBase64: []byte("XKnsiQv2eyA="),
		},
		{
			Data:              []byte("123"),
			EncryptData:       []byte{101, 147, 215, 132, 6, 251, 118, 45},
			EncryptDataHex:    []byte("6593d78406fb762d"),
			EncryptDataBase64: []byte("ZZPXhAb7di0="),
		},
		{
			Data:              []byte("你好，世界"),
			EncryptData:       []byte{176, 28, 68, 100, 166, 67, 156, 148, 46, 244, 26, 37, 38, 97, 62, 68},
			EncryptDataHex:    []byte("b01c4464a6439c942ef41a2526613e44"),
			EncryptDataBase64: []byte("sBxEZKZDnJQu9BolJmE+RA=="),
		},
	}

	encrypt := func(data []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
		return EncryptTripleOFB(data, testTripleKey, testIV, padding, encoding)
	}

	decrypt := func(data []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
		return DecryptTripleOFB(data, testTripleKey, testIV, padding, encoding)
	}

	if err := testEncryptAndDecrypt(t.Name(), encrypt, decrypt, testCases); err != nil {
		t.Fatal(err)
	}
}

// go test -v -cover -run=^TestTripleCTR$
func TestTripleCTR(t *testing.T) {
	testCases := []testCase{
		{
			Data:              []byte(""),
			EncryptData:       []byte{92, 169, 236, 137, 11, 246, 123, 32},
			EncryptDataHex:    []byte("5ca9ec890bf67b20"),
			EncryptDataBase64: []byte("XKnsiQv2eyA="),
		},
		{
			Data:              []byte("123"),
			EncryptData:       []byte{101, 147, 215, 132, 6, 251, 118, 45},
			EncryptDataHex:    []byte("6593d78406fb762d"),
			EncryptDataBase64: []byte("ZZPXhAb7di0="),
		},
		{
			Data:              []byte("你好，世界"),
			EncryptData:       []byte{176, 28, 68, 100, 166, 67, 156, 148, 76, 184, 154, 31, 42, 134, 28, 205},
			EncryptDataHex:    []byte("b01c4464a6439c944cb89a1f2a861ccd"),
			EncryptDataBase64: []byte("sBxEZKZDnJRMuJofKoYczQ=="),
		},
	}

	encrypt := func(data []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
		return EncryptTripleCTR(data, testTripleKey, testIV, padding, encoding)
	}

	decrypt := func(data []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
		return DecryptTripleCTR(data, testTripleKey, testIV, padding, encoding)
	}

	if err := testEncryptAndDecrypt(t.Name(), encrypt, decrypt, testCases); err != nil {
		t.Fatal(err)
	}
}
