// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/FishGoddess/cryptox/bytes/encoding"
	"github.com/FishGoddess/cryptox/bytes/padding"
)

func newBlock(key []byte) (cipher.Block, int, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, 0, err
	}

	blockSize := block.BlockSize()
	return block, blockSize, nil
}

func EncryptECB(bs []byte, key []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
	block, blockSize, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src := bytes.Clone(bs)
	src = padding.Pad(src, blockSize)
	dst := bytes.Clone(src)

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

	dst = encoding.Encode(dst)
	return dst, nil
}

func DecryptECB(bs []byte, key []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
	block, blockSize, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src, err := encoding.Decode(bs)
	if err != nil {
		return nil, err
	}

	dst := bytes.Clone(src)

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

	return padding.Unpad(dst, blockSize)
}

func EncryptCBC(bs []byte, key []byte, iv []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
	block, blockSize, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src := bytes.Clone(bs)
	src = padding.Pad(src, blockSize)
	dst := bytes.Clone(src)

	cipher.NewCBCEncrypter(block, iv).CryptBlocks(dst, src)
	dst = encoding.Encode(dst)
	return dst, nil
}

func DecryptCBC(bs []byte, key []byte, iv []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
	block, blockSize, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src, err := encoding.Decode(bs)
	if err != nil {
		return nil, err
	}

	dst := bytes.Clone(src)

	cipher.NewCBCDecrypter(block, iv).CryptBlocks(dst, src)
	return padding.Unpad(dst, blockSize)
}

func EncryptCFB(bs []byte, key []byte, iv []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
	block, blockSize, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src := bytes.Clone(bs)
	src = padding.Pad(src, blockSize)
	dst := bytes.Clone(src)

	cipher.NewCFBEncrypter(block, iv).XORKeyStream(dst, src)
	dst = encoding.Encode(dst)
	return dst, nil
}

func DecryptCFB(bs []byte, key []byte, iv []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
	block, blockSize, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src, err := encoding.Decode(bs)
	if err != nil {
		return nil, err
	}

	dst := bytes.Clone(src)

	cipher.NewCFBDecrypter(block, iv).XORKeyStream(dst, src)
	return padding.Unpad(dst, blockSize)
}

func EncryptOFB(bs []byte, key []byte, iv []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
	block, blockSize, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src := bytes.Clone(bs)
	src = padding.Pad(src, blockSize)
	dst := bytes.Clone(src)

	cipher.NewOFB(block, iv).XORKeyStream(dst, src)
	dst = encoding.Encode(dst)
	return dst, nil
}

func DecryptOFB(bs []byte, key []byte, iv []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
	block, blockSize, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src, err := encoding.Decode(bs)
	if err != nil {
		return nil, err
	}

	dst := bytes.Clone(src)

	cipher.NewOFB(block, iv).XORKeyStream(dst, src)
	return padding.Unpad(dst, blockSize)
}

func EncryptCTR(bs []byte, key []byte, iv []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
	block, blockSize, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src := bytes.Clone(bs)
	src = padding.Pad(src, blockSize)
	dst := bytes.Clone(src)

	cipher.NewCTR(block, iv).XORKeyStream(dst, src)
	dst = encoding.Encode(dst)
	return dst, nil
}

func DecryptCTR(bs []byte, key []byte, iv []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
	block, blockSize, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src, err := encoding.Decode(bs)
	if err != nil {
		return nil, err
	}

	dst := bytes.Clone(src)

	cipher.NewCTR(block, iv).XORKeyStream(dst, src)
	return padding.Unpad(dst, blockSize)
}

// EncryptGCM uses gcm mode to encrypt bs.
func EncryptGCM(bs []byte, key []byte, nonce []byte, additional []byte, encoding encoding.Encoding) ([]byte, error) {
	block, _, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src := bytes.Clone(bs)
	dst := src[:0]

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	dst = gcm.Seal(dst, nonce, src, additional)
	dst = encoding.Encode(dst)
	return dst, nil
}

// DecryptGCM uses gcm mode to decrypt bs.
func DecryptGCM(bs []byte, key []byte, nonce []byte, additional []byte, encoding encoding.Encoding) ([]byte, error) {
	block, _, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src, err := encoding.Decode(bs)
	if err != nil {
		return nil, err
	}

	dst := bytes.Clone(src)

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(dst, nonce, src, additional)
}
