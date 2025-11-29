// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package aes

import (
	"crypto/aes"
	"fmt"
	"slices"
	"testing"

	"github.com/FishGoddess/cryptox/bytes/encoding"
	"github.com/FishGoddess/cryptox/bytes/padding"
)

var (
	testKey = []byte("123456788765432112345678")
	testIV  = []byte("8765432112345678")
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

	wantBlock, err := aes.NewCipher(testKey)
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
			EncryptData:       []byte{254, 194, 2, 244, 7, 195, 25, 158, 172, 88, 119, 145, 234, 39, 193, 11},
			EncryptDataHex:    []byte("fec202f407c3199eac587791ea27c10b"),
			EncryptDataBase64: []byte("/sIC9AfDGZ6sWHeR6ifBCw=="),
		},
		{
			Data:              []byte("123"),
			EncryptData:       []byte{106, 180, 23, 31, 55, 116, 164, 43, 132, 49, 25, 42, 117, 236, 143, 154},
			EncryptDataHex:    []byte("6ab4171f3774a42b8431192a75ec8f9a"),
			EncryptDataBase64: []byte("arQXHzd0pCuEMRkqdeyPmg=="),
		},
		{
			Data:              []byte("你好，世界"),
			EncryptData:       []byte{100, 112, 82, 33, 74, 230, 164, 206, 182, 33, 100, 255, 171, 204, 229, 193},
			EncryptDataHex:    []byte("647052214ae6a4ceb62164ffabcce5c1"),
			EncryptDataBase64: []byte("ZHBSIUrmpM62IWT/q8zlwQ=="),
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
			EncryptData:       []byte{18, 228, 65, 237, 113, 28, 196, 195, 209, 118, 249, 189, 134, 92, 184, 59},
			EncryptDataHex:    []byte("12e441ed711cc4c3d176f9bd865cb83b"),
			EncryptDataBase64: []byte("EuRB7XEcxMPRdvm9hly4Ow=="),
		},
		{
			Data:              []byte("123"),
			EncryptData:       []byte{239, 166, 198, 112, 30, 48, 8, 15, 67, 248, 202, 52, 213, 118, 239, 235},
			EncryptDataHex:    []byte("efa6c6701e30080f43f8ca34d576efeb"),
			EncryptDataBase64: []byte("76bGcB4wCA9D+Mo01Xbv6w=="),
		},
		{
			Data:              []byte("你好，世界"),
			EncryptData:       []byte{31, 24, 138, 155, 181, 90, 114, 79, 168, 189, 154, 134, 242, 22, 7, 90},
			EncryptDataHex:    []byte("1f188a9bb55a724fa8bd9a86f216075a"),
			EncryptDataBase64: []byte("HxiKm7Vack+ovZqG8hYHWg=="),
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
			EncryptData:       []byte{129, 42, 238, 182, 0, 143, 73, 239, 33, 57, 26, 89, 78, 230, 185, 139},
			EncryptDataHex:    []byte("812aeeb6008f49ef21391a594ee6b98b"),
			EncryptDataBase64: []byte("gSrutgCPSe8hORpZTua5iw=="),
		},
		{
			Data:              []byte("123"),
			EncryptData:       []byte{160, 8, 205, 171, 29, 146, 84, 242, 60, 36, 7, 68, 83, 251, 164, 150},
			EncryptDataHex:    []byte("a008cdab1d9254f23c24074453fba496"),
			EncryptDataBase64: []byte("oAjNqx2SVPI8JAdEU/uklg=="),
		},
		{
			Data:              []byte("你好，世界"),
			EncryptData:       []byte{117, 135, 94, 67, 181, 34, 182, 67, 189, 205, 178, 223, 185, 99, 37, 154},
			EncryptDataHex:    []byte("75875e43b522b643bdcdb2dfb963259a"),
			EncryptDataBase64: []byte("dYdeQ7UitkO9zbLfuWMlmg=="),
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
			EncryptData:       []byte{129, 42, 238, 182, 0, 143, 73, 239, 33, 57, 26, 89, 78, 230, 185, 139},
			EncryptDataHex:    []byte("812aeeb6008f49ef21391a594ee6b98b"),
			EncryptDataBase64: []byte("gSrutgCPSe8hORpZTua5iw=="),
		},
		{
			Data:              []byte("123"),
			EncryptData:       []byte{160, 8, 205, 171, 29, 146, 84, 242, 60, 36, 7, 68, 83, 251, 164, 150},
			EncryptDataHex:    []byte("a008cdab1d9254f23c24074453fba496"),
			EncryptDataBase64: []byte("oAjNqx2SVPI8JAdEU/uklg=="),
		},
		{
			Data:              []byte("你好，世界"),
			EncryptData:       []byte{117, 135, 94, 67, 181, 34, 182, 67, 189, 205, 178, 223, 185, 99, 37, 154},
			EncryptDataHex:    []byte("75875e43b522b643bdcdb2dfb963259a"),
			EncryptDataBase64: []byte("dYdeQ7UitkO9zbLfuWMlmg=="),
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
			EncryptData:       []byte{129, 42, 238, 182, 0, 143, 73, 239, 33, 57, 26, 89, 78, 230, 185, 139},
			EncryptDataHex:    []byte("812aeeb6008f49ef21391a594ee6b98b"),
			EncryptDataBase64: []byte("gSrutgCPSe8hORpZTua5iw=="),
		},
		{
			Data:              []byte("123"),
			EncryptData:       []byte{160, 8, 205, 171, 29, 146, 84, 242, 60, 36, 7, 68, 83, 251, 164, 150},
			EncryptDataHex:    []byte("a008cdab1d9254f23c24074453fba496"),
			EncryptDataBase64: []byte("oAjNqx2SVPI8JAdEU/uklg=="),
		},
		{
			Data:              []byte("你好，世界"),
			EncryptData:       []byte{117, 135, 94, 67, 181, 34, 182, 67, 189, 205, 178, 223, 185, 99, 37, 154},
			EncryptDataHex:    []byte("75875e43b522b643bdcdb2dfb963259a"),
			EncryptDataBase64: []byte("dYdeQ7UitkO9zbLfuWMlmg=="),
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

// go test -v -cover -run=^TestGCM$
func TestGCM(t *testing.T) {
	testCases := []testCase{
		// {
		// 	Data:              []byte(""),
		// 	EncryptData:       []byte{181, 199, 133, 45, 117, 141, 195, 175, 157, 6, 27, 16, 98, 103, 77, 186},
		// 	EncryptDataHex:    []byte("b5c7852d758dc3af9d061b1062674dba"),
		// 	EncryptDataBase64: []byte("+YQqKJgRdgQuYdipoz5HlkO9SQ=="),
		// },
		{
			Data:              []byte("123"),
			EncryptData:       []byte{249, 132, 42, 40, 152, 17, 118, 4, 46, 97, 216, 169, 163, 62, 71, 150, 67, 189, 73},
			EncryptDataHex:    []byte("f9842a28981176042e61d8a9a33e479643bd49"),
			EncryptDataBase64: []byte("+YQqKJgRdgQuYdipoz5HlkO9SQ=="),
		},
		{
			Data:              []byte("你好，世界"),
			EncryptData:       []byte{44, 11, 185, 159, 152, 100, 94, 1, 82, 180, 112, 131, 14, 35, 63, 39, 98, 215, 167, 243, 173, 80, 155, 27, 228, 197, 155, 234, 236, 204, 91},
			EncryptDataHex:    []byte("2c0bb99f98645e0152b470830e233f2762d7a7f3ad509b1be4c59beaeccc5b"),
			EncryptDataBase64: []byte("LAu5n5hkXgFStHCDDiM/J2LXp/OtUJsb5MWb6uzMWw=="),
		},
	}

	nonce := []byte("123456abcdef")
	t.Logf("nonce: %s\n", nonce)

	encrypt := func(data []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
		return EncryptGCM(data, testKey, nonce, nil, encoding)
	}

	decrypt := func(data []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
		return DecryptGCM(data, testKey, nonce, nil, encoding)
	}

	if err := testEncryptAndDecrypt(t.Name(), encrypt, decrypt, testCases); err != nil {
		t.Fatal(err)
	}
}
