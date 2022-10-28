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

// EncryptMode is a function using one mode to encrypt src to dst.
type EncryptMode func(block cipher.Block, iv []byte, src []byte, dst []byte) error

// Crypt crypts src to dst.
func (em EncryptMode) Crypt(block cipher.Block, iv []byte, src []byte, dst []byte) error {
	return em(block, iv, src, dst)
}

// DecryptMode is a function using one mode to encrypt src to dst.
type DecryptMode func(block cipher.Block, iv []byte, src []byte, dst []byte) error

// Crypt crypts src to dst.
func (dm DecryptMode) Crypt(block cipher.Block, iv []byte, src []byte, dst []byte) error {
	return dm(block, iv, src, dst)
}

// EncryptECB is ecb encrypting mode.
func EncryptECB(block cipher.Block, _ []byte, src []byte, dst []byte) error {
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

// DecryptECB is ecb decrypting mode.
func DecryptECB(block cipher.Block, _ []byte, src []byte, dst []byte) error {
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

// EncryptCBC is cbc encrypting mode.
func EncryptCBC(block cipher.Block, iv []byte, src []byte, dst []byte) error {
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(dst, src)
	return nil
}

// DecryptCBC is cbc decrypting mode.
func DecryptCBC(block cipher.Block, iv []byte, src []byte, dst []byte) error {
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(dst, src)
	return nil
}

// EncryptCFB is cfb encrypting mode.
func EncryptCFB(block cipher.Block, iv []byte, src []byte, dst []byte) error {
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(dst, src)
	return nil
}

// DecryptCFB is cfb decrypting mode.
func DecryptCFB(block cipher.Block, iv []byte, src []byte, dst []byte) error {
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(dst, src)
	return nil
}

// EncryptOFB is ofb encrypting mode.
func EncryptOFB(block cipher.Block, iv []byte, src []byte, dst []byte) error {
	cipher.NewOFB(block, iv).XORKeyStream(dst, src)
	return nil
}

// DecryptOFB is ofb decrypting mode.
func DecryptOFB(block cipher.Block, iv []byte, src []byte, dst []byte) error {
	cipher.NewOFB(block, iv).XORKeyStream(dst, src)
	return nil
}

// EncryptCTR is ctr encrypting mode.
func EncryptCTR(block cipher.Block, iv []byte, src []byte, dst []byte) error {
	cipher.NewCTR(block, iv).XORKeyStream(dst, src)
	return nil
}

// DecryptCTR is ctr decrypting mode.
func DecryptCTR(block cipher.Block, iv []byte, src []byte, dst []byte) error {
	cipher.NewCTR(block, iv).XORKeyStream(dst, src)
	return nil
}
