// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import (
	"crypto/cipher"
	"fmt"
)

var (
	_ EncryptMode = EncryptECB
	_ EncryptMode = EncryptCBC
	_ EncryptMode = EncryptCFB
	_ EncryptMode = EncryptOFB
	_ EncryptMode = EncryptCTR
)

var (
	_ DecryptMode = DecryptECB
	_ DecryptMode = DecryptCBC
	_ DecryptMode = DecryptCFB
	_ DecryptMode = DecryptOFB
	_ DecryptMode = DecryptCTR
)

type EncryptMode func(block cipher.Block, iv []byte, src []byte, dst []byte) error

func (em EncryptMode) Crypt(block cipher.Block, iv []byte, src []byte, dst []byte) error {
	return em(block, iv, src, dst)
}

type DecryptMode func(block cipher.Block, iv []byte, src []byte, dst []byte) error

func (dm DecryptMode) Crypt(block cipher.Block, iv []byte, src []byte, dst []byte) error {
	return dm(block, iv, src, dst)
}

func EncryptECB(block cipher.Block, iv []byte, src []byte, dst []byte) error {
	blockSize := block.BlockSize()

	if len(src)%blockSize != 0 {
		return fmt.Errorf("cryptox.encryptECB: len(src) %d %% blockSize %d != 0", len(src), blockSize)
	}

	start := 0
	end := blockSize

	for end <= len(src) {
		block.Encrypt(dst[start:end], src[start:end])

		start += blockSize
		end += blockSize
	}

	return nil
}

func DecryptECB(block cipher.Block, iv []byte, src []byte, dst []byte) error {
	blockSize := block.BlockSize()

	if len(src)%blockSize != 0 {
		return fmt.Errorf("cryptox.decryptECB: len(src) %d %% blockSize %d != 0", len(src), blockSize)
	}

	start := 0
	end := blockSize

	for end <= len(src) {
		block.Decrypt(dst[start:end], src[start:end])

		start += blockSize
		end += blockSize
	}

	return nil
}

func EncryptCBC(block cipher.Block, iv []byte, src []byte, dst []byte) error {
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(dst, src)
	return nil
}

func DecryptCBC(block cipher.Block, iv []byte, src []byte, dst []byte) error {
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(dst, src)
	return nil
}

func EncryptCFB(block cipher.Block, iv []byte, src []byte, dst []byte) error {
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(dst, src)
	return nil
}

func DecryptCFB(block cipher.Block, iv []byte, src []byte, dst []byte) error {
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(dst, src)
	return nil
}

func EncryptOFB(block cipher.Block, iv []byte, src []byte, dst []byte) error {
	cipher.NewOFB(block, iv).XORKeyStream(dst, src)
	return nil
}

func DecryptOFB(block cipher.Block, iv []byte, src []byte, dst []byte) error {
	cipher.NewOFB(block, iv).XORKeyStream(dst, src)
	return nil
}

func EncryptCTR(block cipher.Block, iv []byte, src []byte, dst []byte) error {
	cipher.NewCTR(block, iv).XORKeyStream(dst, src)
	return nil
}

func DecryptCTR(block cipher.Block, iv []byte, src []byte, dst []byte) error {
	cipher.NewCTR(block, iv).XORKeyStream(dst, src)
	return nil
}
