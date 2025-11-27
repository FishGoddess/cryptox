// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package des

import (
	"crypto/des"
	"fmt"
	"slices"
	"testing"

	"github.com/FishGoddess/cryptox"
	"github.com/FishGoddess/cryptox/bytes/encoding"
	"github.com/FishGoddess/cryptox/bytes/padding"
)

var (
	testKey = []byte("12345678")
	testIV  = []byte("87654321")
)

type testCase struct {
	Data              []byte
	EncryptData       []byte
	EncryptDataHex    []byte
	EncryptDataBase64 []byte
}

type testEncryptFunc func(data []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error)

type testDecryptFunc func(data []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error)

func testEncryptAndDecrypt(name string, encrypt testEncryptFunc, decrypt testDecryptFunc, testCases []testCase) error {
	for _, testCase := range testCases {
		// None
		encrypted, err := encrypt(testCase.Data, padding.PKCS7, encoding.None)
		if err != nil {
			return err
		}

		if !slices.Equal(encrypted, testCase.EncryptData) {
			return fmt.Errorf("%s data %q: got %+v != expect %+v", name, testCase.Data, encrypted, testCase.EncryptData)
		}

		decrypted, err := decrypt(encrypted, padding.PKCS7, encoding.None)
		if err != nil {
			return err
		}

		if !slices.Equal(decrypted, testCase.Data) {
			return fmt.Errorf("%s encrypted %q: got %+v != expect %+v", name, encrypted, decrypted, testCase.Data)
		}

		// Hex
		encrypted, err = encrypt(testCase.Data, padding.PKCS7, encoding.Hex)
		if err != nil {
			return err
		}

		if !slices.Equal(encrypted, testCase.EncryptDataHex) {
			return fmt.Errorf("%s data hex %q: got %s != expect %s", name, testCase.Data, encrypted, testCase.EncryptDataHex)
		}

		decrypted, err = decrypt(encrypted, padding.PKCS7, encoding.Hex)
		if err != nil {
			return err
		}

		if !slices.Equal(decrypted, testCase.Data) {
			return fmt.Errorf("%s encrypted hex %q: got %s != expect %s", name, encrypted, decrypted, testCase.Data)
		}

		// Base64
		encrypted, err = encrypt(testCase.Data, padding.PKCS7, encoding.Base64)
		if err != nil {
			return err
		}

		if !slices.Equal(encrypted, testCase.EncryptDataBase64) {
			return fmt.Errorf("%s data base64 %q: got %s != expect %s", name, testCase.Data, encrypted, testCase.EncryptDataBase64)
		}

		decrypted, err = decrypt(encrypted, padding.PKCS7, encoding.Base64)
		if err != nil {
			return err
		}

		if !slices.Equal(decrypted, testCase.Data) {
			return fmt.Errorf("%s encrypted base64 %q: got %s != expect %s", name, encrypted, decrypted, testCase.Data)
		}
	}

	return nil
}

type testResult struct {
	bs           []byte
	hexString    string
	base64String string
}

func (tr *testResult) compareTo(bs cryptox.Bytes) error {
	if string(tr.bs) != string(bs) {
		return fmt.Errorf("result bs %s != bs %s", tr.bs, bs)
	}

	if tr.hexString != bs.Hex() {
		return fmt.Errorf("result hexString %s != bs hex %s", tr.hexString, bs.Hex())
	}

	if tr.base64String != bs.Base64() {
		return fmt.Errorf("result base64String %s != bs base64 %s", tr.base64String, bs.Base64())
	}

	return nil
}

// go test -v -cover -run=^TestNewBlock$
func TestNewBlock(t *testing.T) {
	block, blockSize, err := newBlock(testKey)
	if err != nil {
		t.Fatal(err)
	}

	if block == nil {
		t.Fatal("block == nil")
	}

	if blockSize != block.BlockSize() {
		t.Fatalf("blockSize %d != block.BlockSize() %d", blockSize, block.BlockSize())
	}

	wantBlock, err := des.NewCipher(testKey)
	if err != nil {
		t.Fatal(err)
	}

	if blockSize != wantBlock.BlockSize() {
		t.Fatalf("blockSize %d != wantBlock.BlockSize() %d", blockSize, wantBlock.BlockSize())
	}
}

// go test -v -cover -run=^TestECB$
func TestECB(t *testing.T) {
	testCases := []testCase{
		{
			Data:              []byte(""),
			EncryptData:       []byte{254, 185, 89, 183, 212, 100, 47, 203},
			EncryptDataHex:    []byte("feb959b7d4642fcb"),
			EncryptDataBase64: []byte("/rlZt9RkL8s="),
		},
		{
			Data:              []byte("123"),
			EncryptData:       []byte{44, 56, 133, 81, 215, 244, 137, 236},
			EncryptDataHex:    []byte("2c388551d7f489ec"),
			EncryptDataBase64: []byte("LDiFUdf0iew="),
		},
		{
			Data:              []byte("你好，世界"),
			EncryptData:       []byte{109, 82, 56, 231, 116, 36, 60, 100, 116, 149, 15, 240, 198, 38, 198, 204},
			EncryptDataHex:    []byte("6d5238e774243c6474950ff0c626c6cc"),
			EncryptDataBase64: []byte("bVI453QkPGR0lQ/wxibGzA=="),
		},
	}

	encrypt := func(data []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
		return EncryptECB(data, testKey, padding, encoding)
	}

	decrypt := func(data []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
		return DecryptECB(data, testKey, padding, encoding)
	}

	if err := testEncryptAndDecrypt(t.Name(), encrypt, decrypt, testCases); err != nil {
		t.Fatal(err)
	}
}

// go test -v -cover -run=^TestCBC$
func TestCBC(t *testing.T) {
	testCases := []testCase{
		{
			Data:              []byte(""),
			EncryptData:       []byte{205, 172, 198, 131, 218, 176, 175, 188},
			EncryptDataHex:    []byte("cdacc683dab0afbc"),
			EncryptDataBase64: []byte("zazGg9qwr7w="),
		},
		{
			Data:              []byte("123"),
			EncryptData:       []byte{243, 126, 30, 174, 181, 95, 17, 128},
			EncryptDataHex:    []byte("f37e1eaeb55f1180"),
			EncryptDataBase64: []byte("834errVfEYA="),
		},
		{
			Data:              []byte("你好，世界"),
			EncryptData:       []byte{185, 108, 29, 112, 42, 71, 169, 240, 62, 215, 156, 154, 145, 88, 110, 10},
			EncryptDataHex:    []byte("b96c1d702a47a9f03ed79c9a91586e0a"),
			EncryptDataBase64: []byte("uWwdcCpHqfA+15yakVhuCg=="),
		},
	}

	encrypt := func(data []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
		return EncryptCBC(data, testKey, testIV, padding, encoding)
	}

	decrypt := func(data []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
		return DecryptCBC(data, testKey, testIV, padding, encoding)
	}

	if err := testEncryptAndDecrypt(t.Name(), encrypt, decrypt, testCases); err != nil {
		t.Fatal(err)
	}
}

// go test -v -cover -run=^TestCFB$
func TestCFB(t *testing.T) {
	testCases := []testCase{
		{
			Data:              []byte(""),
			EncryptData:       []byte{48, 92, 56, 32, 147, 125, 156, 44},
			EncryptDataHex:    []byte("305c3820937d9c2c"),
			EncryptDataBase64: []byte("MFw4IJN9nCw="),
		},
		{
			Data:              []byte("123"),
			EncryptData:       []byte{9, 102, 3, 45, 158, 112, 145, 33},
			EncryptDataHex:    []byte("0966032d9e709121"),
			EncryptDataBase64: []byte("CWYDLZ5wkSE="),
		},
		{
			Data:              []byte("你好，世界"),
			EncryptData:       []byte{220, 233, 144, 205, 62, 200, 123, 152, 231, 237, 219, 68, 211, 43, 255, 25},
			EncryptDataHex:    []byte("dce990cd3ec87b98e7eddb44d32bff19"),
			EncryptDataBase64: []byte("3OmQzT7Ie5jn7dtE0yv/GQ=="),
		},
	}

	encrypt := func(data []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
		return EncryptCFB(data, testKey, testIV, padding, encoding)
	}

	decrypt := func(data []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
		return DecryptCFB(data, testKey, testIV, padding, encoding)
	}

	if err := testEncryptAndDecrypt(t.Name(), encrypt, decrypt, testCases); err != nil {
		t.Fatal(err)
	}
}

// go test -v -cover -run=^TestOFB$
func TestOFB(t *testing.T) {
	testCases := []testCase{
		{
			Data:              []byte(""),
			EncryptData:       []byte{48, 92, 56, 32, 147, 125, 156, 44},
			EncryptDataHex:    []byte("305c3820937d9c2c"),
			EncryptDataBase64: []byte("MFw4IJN9nCw="),
		},
		{
			Data:              []byte("123"),
			EncryptData:       []byte{9, 102, 3, 45, 158, 112, 145, 33},
			EncryptDataHex:    []byte("0966032d9e709121"),
			EncryptDataBase64: []byte("CWYDLZ5wkSE="),
		},
		{
			Data:              []byte("你好，世界"),
			EncryptData:       []byte{220, 233, 144, 205, 62, 200, 123, 152, 169, 42, 97, 1, 193, 120, 15, 149},
			EncryptDataHex:    []byte("dce990cd3ec87b98a92a6101c1780f95"),
			EncryptDataBase64: []byte("3OmQzT7Ie5ipKmEBwXgPlQ=="),
		},
	}

	encrypt := func(data []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
		return EncryptOFB(data, testKey, testIV, padding, encoding)
	}

	decrypt := func(data []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
		return DecryptOFB(data, testKey, testIV, padding, encoding)
	}

	if err := testEncryptAndDecrypt(t.Name(), encrypt, decrypt, testCases); err != nil {
		t.Fatal(err)
	}
}

// go test -v -cover -run=^TestCTR$
func TestCTR(t *testing.T) {
	testCases := []testCase{
		{
			Data:              []byte(""),
			EncryptData:       []byte{48, 92, 56, 32, 147, 125, 156, 44},
			EncryptDataHex:    []byte("305c3820937d9c2c"),
			EncryptDataBase64: []byte("MFw4IJN9nCw="),
		},
		{
			Data:              []byte("123"),
			EncryptData:       []byte{9, 102, 3, 45, 158, 112, 145, 33},
			EncryptDataHex:    []byte("0966032d9e709121"),
			EncryptDataBase64: []byte("CWYDLZ5wkSE="),
		},
		{
			Data:              []byte("你好，世界"),
			EncryptData:       []byte{220, 233, 144, 205, 62, 200, 123, 152, 82, 201, 236, 67, 30, 240, 63, 228},
			EncryptDataHex:    []byte("dce990cd3ec87b9852c9ec431ef03fe4"),
			EncryptDataBase64: []byte("3OmQzT7Ie5hSyexDHvA/5A=="),
		},
	}

	encrypt := func(data []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
		return EncryptCTR(data, testKey, testIV, padding, encoding)
	}

	decrypt := func(data []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
		return DecryptCTR(data, testKey, testIV, padding, encoding)
	}

	if err := testEncryptAndDecrypt(t.Name(), encrypt, decrypt, testCases); err != nil {
		t.Fatal(err)
	}
}
