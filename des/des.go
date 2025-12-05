// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package des

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
)

func newBlock(key []byte) (cipher.Block, int, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, 0, err
	}

	blockSize := block.BlockSize()
	return block, blockSize, nil
}

// EncryptECB uses ecb mode to encrypt data.
// It must specify a padding.
func EncryptECB(data []byte, key []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, blockSize, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src := bytes.Clone(data)
	src = conf.padding.Pad(src, blockSize)
	dst := bytes.Clone(src)

	if len(src)%blockSize != 0 {
		return nil, fmt.Errorf("cryptox/des: encrypt ecb len(src) %d %% blockSize %d != 0", len(src), blockSize)
	}

	start := 0
	end := blockSize

	for end <= len(src) {
		block.Encrypt(dst[start:end], src[start:end])

		start += blockSize
		end += blockSize
	}

	dst = conf.encoding.Encode(dst)
	return dst, nil
}

// EncryptCBC uses cbc mode to encrypt data.
// It must specify a padding.
func EncryptCBC(data []byte, key []byte, iv []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, blockSize, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src := bytes.Clone(data)
	src = conf.padding.Pad(src, blockSize)
	dst := bytes.Clone(src)

	cipher.NewCBCEncrypter(block, iv).CryptBlocks(dst, src)
	dst = conf.encoding.Encode(dst)
	return dst, nil
}

// EncryptCFB uses cfb mode to encrypt data.
// There is no need to specify a padding.
func EncryptCFB(data []byte, key []byte, iv []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, _, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src := bytes.Clone(data)
	dst := bytes.Clone(src)

	cipher.NewCFBEncrypter(block, iv).XORKeyStream(dst, src)
	dst = conf.encoding.Encode(dst)
	return dst, nil
}

// EncryptOFB uses ofb mode to encrypt data.
// There is no need to specify a padding.
func EncryptOFB(data []byte, key []byte, iv []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, _, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src := bytes.Clone(data)
	dst := bytes.Clone(src)

	cipher.NewOFB(block, iv).XORKeyStream(dst, src)
	dst = conf.encoding.Encode(dst)
	return dst, nil
}

// EncryptCTR uses ctr mode to encrypt data.
// There is no need to specify a padding.
func EncryptCTR(data []byte, key []byte, iv []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, _, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src := bytes.Clone(data)
	dst := bytes.Clone(src)

	cipher.NewCTR(block, iv).XORKeyStream(dst, src)
	dst = conf.encoding.Encode(dst)
	return dst, nil
}

// DecryptECB uses ecb mode to decrypt data.
// It must specify a padding.
func DecryptECB(data []byte, key []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, blockSize, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src, err := conf.encoding.Decode(data)
	if err != nil {
		return nil, err
	}

	dst := bytes.Clone(src)

	if len(src)%blockSize != 0 {
		return nil, fmt.Errorf("cryptox/des: decrypt ecb len(src) %d %% blockSize %d != 0", len(src), blockSize)
	}

	start := 0
	end := blockSize

	for end <= len(src) {
		block.Decrypt(dst[start:end], src[start:end])

		start += blockSize
		end += blockSize
	}

	return conf.padding.Unpad(dst, blockSize)
}

// DecryptCBC uses cbc mode to decrypt data.
// It must specify a padding.
func DecryptCBC(data []byte, key []byte, iv []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, blockSize, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src, err := conf.encoding.Decode(data)
	if err != nil {
		return nil, err
	}

	dst := bytes.Clone(src)

	cipher.NewCBCDecrypter(block, iv).CryptBlocks(dst, src)
	return conf.padding.Unpad(dst, blockSize)
}

// DecryptCFB uses cfb mode to decrypt data.
// There is no need to specify a padding.
func DecryptCFB(data []byte, key []byte, iv []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, _, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src, err := conf.encoding.Decode(data)
	if err != nil {
		return nil, err
	}

	dst := bytes.Clone(src)

	cipher.NewCFBDecrypter(block, iv).XORKeyStream(dst, src)
	return dst, nil
}

// DecryptOFB uses ofb mode to decrypt data.
// There is no need to specify a padding.
func DecryptOFB(data []byte, key []byte, iv []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, _, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src, err := conf.encoding.Decode(data)
	if err != nil {
		return nil, err
	}

	dst := bytes.Clone(src)

	cipher.NewOFB(block, iv).XORKeyStream(dst, src)
	return dst, nil
}

// DecryptCTR uses ctr mode to decrypt data.
// There is no need to specify a padding.
func DecryptCTR(data []byte, key []byte, iv []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, _, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src, err := conf.encoding.Decode(data)
	if err != nil {
		return nil, err
	}

	dst := bytes.Clone(src)

	cipher.NewCTR(block, iv).XORKeyStream(dst, src)
	return dst, nil
}
