// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package des

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"fmt"

	"github.com/FishGoddess/cryptox/bytes/encoding"
	"github.com/FishGoddess/cryptox/bytes/padding"
)

func newTripleBlock(key []byte) (cipher.Block, int, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, 0, err
	}

	blockSize := block.BlockSize()
	return block, blockSize, nil
}

// EncryptTripleECB uses ecb mode to encrypt bs.
func EncryptTripleECB(bs []byte, key []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
	block, blockSize, err := newTripleBlock(key)
	if err != nil {
		return nil, err
	}

	src := bytes.Clone(bs)
	src = padding.Pad(src, blockSize)
	dst := bytes.Clone(src)

	if len(src)%blockSize != 0 {
		return nil, fmt.Errorf("cryptox/des: encrypt ecb triple len(src) %d %% blockSize %d != 0", len(src), blockSize)
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

// DecryptTripleECB uses ecb mode to decrypt bs.
func DecryptTripleECB(bs []byte, key []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
	block, blockSize, err := newTripleBlock(key)
	if err != nil {
		return nil, err
	}

	src, err := encoding.Decode(bs)
	if err != nil {
		return nil, err
	}

	dst := bytes.Clone(src)

	if len(src)%blockSize != 0 {
		return nil, fmt.Errorf("cryptox/des: decrypt ecb triple len(src) %d %% blockSize %d != 0", len(src), blockSize)
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

// EncryptTripleCBC uses cbc mode to encrypt bs.
func EncryptTripleCBC(bs []byte, key []byte, iv []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
	block, blockSize, err := newTripleBlock(key)
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

// DecryptTripleCBC uses cbc mode to decrypt bs.
func DecryptTripleCBC(bs []byte, key []byte, iv []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
	block, blockSize, err := newTripleBlock(key)
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

// EncryptTripleCFB uses cfb mode to encrypt bs.
func EncryptTripleCFB(bs []byte, key []byte, iv []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
	block, blockSize, err := newTripleBlock(key)
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

// DecryptTripleCFB uses cfb mode to decrypt bs.
func DecryptTripleCFB(bs []byte, key []byte, iv []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
	block, blockSize, err := newTripleBlock(key)
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

// EncryptTripleOFB uses ofb mode to encrypt bs.
func EncryptTripleOFB(bs []byte, key []byte, iv []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
	block, blockSize, err := newTripleBlock(key)
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

// DecryptTripleOFB uses ofb mode to decrypt bs.
func DecryptTripleOFB(bs []byte, key []byte, iv []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
	block, blockSize, err := newTripleBlock(key)
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

// EncryptTripleCTR uses ctr mode to encrypt bs.
func EncryptTripleCTR(bs []byte, key []byte, iv []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
	block, blockSize, err := newTripleBlock(key)
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

// DecryptTripleCTR uses ctr mode to decrypt bs.
func DecryptTripleCTR(bs []byte, key []byte, iv []byte, padding padding.Padding, encoding encoding.Encoding) ([]byte, error) {
	block, blockSize, err := newTripleBlock(key)
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
