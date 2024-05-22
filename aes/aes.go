// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/FishGoddess/cryptox"
)

func newBlock(key cryptox.Bytes) (cipher.Block, int, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, 0, err
	}

	blockSize := block.BlockSize()
	return block, blockSize, nil
}

func EncryptECB(key cryptox.Bytes, padding cryptox.Padding, bs cryptox.Bytes) (cryptox.Bytes, error) {
	block, blockSize, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src := padding.Padding(bs, blockSize)
	dst := src.Clone()

	if len(src)%blockSize != 0 {
		return nil, fmt.Errorf("cryptox/aes: encrypt ecb len(src) %d %% blockSize %d != 0", len(src), blockSize)
	}

	start := 0
	end := blockSize

	for end <= len(src) {
		block.Encrypt(dst[start:end], src[start:end])

		start += blockSize
		end += blockSize
	}

	return dst, nil
}

func DecryptECB(key cryptox.Bytes, padding cryptox.Padding, bs cryptox.Bytes) (cryptox.Bytes, error) {
	block, blockSize, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src := bs
	dst := bs.Clone()

	if len(src)%blockSize != 0 {
		return nil, fmt.Errorf("cryptox/aes: decrypt ecb len(src) %d %% blockSize %d != 0", len(src), blockSize)
	}

	start := 0
	end := blockSize

	for end <= len(src) {
		block.Decrypt(dst[start:end], src[start:end])

		start += blockSize
		end += blockSize
	}

	return padding.UndoPadding(dst, blockSize)
}

func EncryptCBC(key cryptox.Bytes, iv cryptox.Bytes, padding cryptox.Padding, bs cryptox.Bytes) (cryptox.Bytes, error) {
	block, blockSize, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src := padding.Padding(bs, blockSize)
	dst := src.Clone()

	cipher.NewCBCEncrypter(block, iv).CryptBlocks(dst, src)
	return dst, nil
}

func DecryptCBC(key cryptox.Bytes, iv cryptox.Bytes, padding cryptox.Padding, bs cryptox.Bytes) (cryptox.Bytes, error) {
	block, blockSize, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src := bs
	dst := src.Clone()

	cipher.NewCBCDecrypter(block, iv).CryptBlocks(dst, src)
	return padding.UndoPadding(dst, blockSize)
}

func EncryptCFB(key cryptox.Bytes, iv cryptox.Bytes, padding cryptox.Padding, bs cryptox.Bytes) (cryptox.Bytes, error) {
	block, blockSize, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src := padding.Padding(bs, blockSize)
	dst := src.Clone()

	cipher.NewCFBEncrypter(block, iv).XORKeyStream(dst, src)
	return dst, nil
}

func DecryptCFB(key cryptox.Bytes, iv cryptox.Bytes, padding cryptox.Padding, bs cryptox.Bytes) (cryptox.Bytes, error) {
	block, blockSize, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src := bs
	dst := bs.Clone()

	cipher.NewCFBDecrypter(block, iv).XORKeyStream(dst, src)
	return padding.UndoPadding(dst, blockSize)
}

func EncryptOFB(key cryptox.Bytes, iv cryptox.Bytes, padding cryptox.Padding, bs cryptox.Bytes) (cryptox.Bytes, error) {
	block, blockSize, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src := padding.Padding(bs, blockSize)
	dst := src.Clone()

	cipher.NewOFB(block, iv).XORKeyStream(dst, src)
	return dst, nil
}

func DecryptOFB(key cryptox.Bytes, iv cryptox.Bytes, padding cryptox.Padding, bs cryptox.Bytes) (cryptox.Bytes, error) {
	block, blockSize, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src := bs
	dst := bs.Clone()

	cipher.NewOFB(block, iv).XORKeyStream(dst, src)
	return padding.UndoPadding(dst, blockSize)
}

func EncryptCTR(key cryptox.Bytes, iv cryptox.Bytes, padding cryptox.Padding, bs cryptox.Bytes) (cryptox.Bytes, error) {
	block, blockSize, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src := padding.Padding(bs, blockSize)
	dst := src.Clone()

	cipher.NewCTR(block, iv).XORKeyStream(dst, src)
	return dst, nil
}

func DecryptCTR(key cryptox.Bytes, iv cryptox.Bytes, padding cryptox.Padding, bs cryptox.Bytes) (cryptox.Bytes, error) {
	block, blockSize, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src := bs
	dst := bs.Clone()

	cipher.NewCTR(block, iv).XORKeyStream(dst, src)
	return padding.UndoPadding(dst, blockSize)
}

// EncryptGCM uses gcm mode to encrypt bs.
func EncryptGCM(key cryptox.Bytes, nonce cryptox.Bytes, additional cryptox.Bytes, bs cryptox.Bytes) (cryptox.Bytes, error) {
	block, _, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src := bs.Clone()
	dst := src[:0]

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	dst = gcm.Seal(dst, nonce, src, additional)
	return dst, nil
}

// DecryptGCM uses gcm mode to decrypt bs.
func DecryptGCM(key cryptox.Bytes, nonce cryptox.Bytes, additional cryptox.Bytes, bs cryptox.Bytes) (cryptox.Bytes, error) {
	block, _, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src := bs.Clone()
	dst := src[:0]

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(dst, nonce, src, additional)
}
