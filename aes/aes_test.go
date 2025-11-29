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
	testKey = []byte("12345678876543211234567887654321")
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
			EncryptData:       []byte{46, 71, 207, 219, 18, 238, 77, 216, 177, 177, 186, 232, 19, 197, 96, 172},
			EncryptDataHex:    []byte("2e47cfdb12ee4dd8b1b1bae813c560ac"),
			EncryptDataBase64: []byte("LkfP2xLuTdixsbroE8VgrA=="),
		},
		{
			Data:              []byte("123"),
			EncryptData:       []byte{173, 62, 123, 195, 111, 6, 34, 76, 86, 148, 68, 12, 179, 251, 241, 79},
			EncryptDataHex:    []byte("ad3e7bc36f06224c5694440cb3fbf14f"),
			EncryptDataBase64: []byte("rT57w28GIkxWlEQMs/vxTw=="),
		},
		{
			Data:              []byte("你好，世界"),
			EncryptData:       []byte{219, 84, 167, 180, 5, 230, 163, 133, 6, 168, 131, 20, 69, 151, 26, 163},
			EncryptDataHex:    []byte("db54a7b405e6a38506a8831445971aa3"),
			EncryptDataBase64: []byte("21SntAXmo4UGqIMURZcaow=="),
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
			EncryptData:       []byte{204, 67, 101, 243, 145, 108, 173, 196, 169, 232, 196, 238, 119, 228, 54, 135},
			EncryptDataHex:    []byte("cc4365f3916cadc4a9e8c4ee77e43687"),
			EncryptDataBase64: []byte("zENl85FsrcSp6MTud+Q2hw=="),
		},
		{
			Data:              []byte("123"),
			EncryptData:       []byte{75, 118, 159, 30, 23, 149, 246, 32, 15, 157, 198, 43, 188, 232, 232, 176},
			EncryptDataHex:    []byte("4b769f1e1795f6200f9dc62bbce8e8b0"),
			EncryptDataBase64: []byte("S3afHheV9iAPncYrvOjosA=="),
		},
		{
			Data:              []byte("你好，世界"),
			EncryptData:       []byte{102, 137, 142, 49, 76, 207, 80, 189, 78, 85, 77, 31, 166, 172, 180, 144},
			EncryptDataHex:    []byte("66898e314ccf50bd4e554d1fa6acb490"),
			EncryptDataBase64: []byte("ZomOMUzPUL1OVU0fpqy0kA=="),
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
			EncryptData:       []byte{77, 179, 6, 120, 99, 255, 246, 149, 205, 253, 145, 227, 5, 180, 233, 252},
			EncryptDataHex:    []byte("4db3067863fff695cdfd91e305b4e9fc"),
			EncryptDataBase64: []byte("TbMGeGP/9pXN/ZHjBbTp/A=="),
		},
		{
			Data:              []byte("123"),
			EncryptData:       []byte{108, 145, 37, 101, 126, 226, 235, 136, 208, 224, 140, 254, 24, 169, 244, 225},
			EncryptDataHex:    []byte("6c9125657ee2eb88d0e08cfe18a9f4e1"),
			EncryptDataBase64: []byte("bJElZX7i64jQ4Iz+GKn04Q=="),
		},
		{
			Data:              []byte("你好，世界"),
			EncryptData:       []byte{185, 30, 182, 141, 214, 82, 9, 57, 81, 9, 57, 101, 242, 49, 117, 237},
			EncryptDataHex:    []byte("b91eb68dd652093951093965f23175ed"),
			EncryptDataBase64: []byte("uR62jdZSCTlRCTll8jF17Q=="),
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
			EncryptData:       []byte{77, 179, 6, 120, 99, 255, 246, 149, 205, 253, 145, 227, 5, 180, 233, 252},
			EncryptDataHex:    []byte("4db3067863fff695cdfd91e305b4e9fc"),
			EncryptDataBase64: []byte("TbMGeGP/9pXN/ZHjBbTp/A=="),
		},
		{
			Data:              []byte("123"),
			EncryptData:       []byte{108, 145, 37, 101, 126, 226, 235, 136, 208, 224, 140, 254, 24, 169, 244, 225},
			EncryptDataHex:    []byte("6c9125657ee2eb88d0e08cfe18a9f4e1"),
			EncryptDataBase64: []byte("bJElZX7i64jQ4Iz+GKn04Q=="),
		},
		{
			Data:              []byte("你好，世界"),
			EncryptData:       []byte{185, 30, 182, 141, 214, 82, 9, 57, 81, 9, 57, 101, 242, 49, 117, 237},
			EncryptDataHex:    []byte("b91eb68dd652093951093965f23175ed"),
			EncryptDataBase64: []byte("uR62jdZSCTlRCTll8jF17Q=="),
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
			EncryptData:       []byte{77, 179, 6, 120, 99, 255, 246, 149, 205, 253, 145, 227, 5, 180, 233, 252},
			EncryptDataHex:    []byte("4db3067863fff695cdfd91e305b4e9fc"),
			EncryptDataBase64: []byte("TbMGeGP/9pXN/ZHjBbTp/A=="),
		},
		{
			Data:              []byte("123"),
			EncryptData:       []byte{108, 145, 37, 101, 126, 226, 235, 136, 208, 224, 140, 254, 24, 169, 244, 225},
			EncryptDataHex:    []byte("6c9125657ee2eb88d0e08cfe18a9f4e1"),
			EncryptDataBase64: []byte("bJElZX7i64jQ4Iz+GKn04Q=="),
		},
		{
			Data:              []byte("你好，世界"),
			EncryptData:       []byte{185, 30, 182, 141, 214, 82, 9, 57, 81, 9, 57, 101, 242, 49, 117, 237},
			EncryptDataHex:    []byte("b91eb68dd652093951093965f23175ed"),
			EncryptDataBase64: []byte("uR62jdZSCTlRCTll8jF17Q=="),
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
		{
			Data:              []byte(""),
			EncryptData:       []byte{135, 179, 184, 127, 41, 243, 84, 60, 61, 129, 163, 91, 171, 195, 246, 98},
			EncryptDataHex:    []byte("87b3b87f29f3543c3d81a35babc3f662"),
			EncryptDataBase64: []byte("h7O4fynzVDw9gaNbq8P2Yg=="),
		},
		{
			Data:              []byte("123"),
			EncryptData:       []byte{224, 234, 86, 29, 157, 167, 33, 35, 34, 123, 227, 204, 243, 177, 205, 151, 173, 141, 174},
			EncryptDataHex:    []byte("e0ea561d9da72123227be3ccf3b1cd97ad8dae"),
			EncryptDataBase64: []byte("4OpWHZ2nISMie+PM87HNl62Nrg=="),
		},
		{
			Data:              []byte("你好，世界"),
			EncryptData:       []byte{53, 101, 197, 113, 143, 115, 148, 86, 178, 196, 74, 153, 208, 219, 180, 14, 230, 66, 70, 95, 244, 28, 225, 107, 243, 182, 147, 187, 199, 202, 220},
			EncryptDataHex:    []byte("3565c5718f739456b2c44a99d0dbb40ee642465ff41ce16bf3b693bbc7cadc"),
			EncryptDataBase64: []byte("NWXFcY9zlFayxEqZ0Nu0DuZCRl/0HOFr87aTu8fK3A=="),
		},
	}

	nonce := []byte("123456abcdef")
	additional := []byte("8765432112345678")

	encrypt := func(data []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
		return EncryptGCM(data, testKey, nonce, additional, encoding)
	}

	decrypt := func(data []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
		return DecryptGCM(data, testKey, nonce, additional, encoding)
	}

	if err := testEncryptAndDecrypt(t.Name(), encrypt, decrypt, testCases); err != nil {
		t.Fatal(err)
	}
}
