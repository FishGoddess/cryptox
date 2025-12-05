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

func newTripleBlock(key []byte) (cipher.Block, int, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, 0, err
	}

	blockSize := block.BlockSize()
	return block, blockSize, nil
}

// EncryptTripleECB uses ecb mode to encrypt data.
// It must specify a padding.
func EncryptTripleECB(data []byte, key []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, blockSize, err := newTripleBlock(key)
	if err != nil {
		return nil, err
	}

	src := bytes.Clone(data)
	src = conf.padding.Pad(src, blockSize)
	dst := bytes.Clone(src)

	if len(src)%blockSize != 0 {
		return nil, fmt.Errorf("cryptox/des: encrypt triple ecb len(src) %d %% blockSize %d != 0", len(src), blockSize)
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

// EncryptTripleCBC uses cbc mode to encrypt data.
// It must specify a padding.
func EncryptTripleCBC(data []byte, key []byte, iv []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, blockSize, err := newTripleBlock(key)
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

// EncryptTripleCFB uses cfb mode to encrypt data.
// There is no need to specify a padding.
func EncryptTripleCFB(data []byte, key []byte, iv []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, _, err := newTripleBlock(key)
	if err != nil {
		return nil, err
	}

	src := bytes.Clone(data)
	dst := bytes.Clone(src)

	cipher.NewCFBEncrypter(block, iv).XORKeyStream(dst, src)
	dst = conf.encoding.Encode(dst)
	return dst, nil
}

// EncryptTripleOFB uses ofb mode to encrypt data.
// There is no need to specify a padding.
func EncryptTripleOFB(data []byte, key []byte, iv []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, _, err := newTripleBlock(key)
	if err != nil {
		return nil, err
	}

	src := bytes.Clone(data)
	dst := bytes.Clone(src)

	cipher.NewOFB(block, iv).XORKeyStream(dst, src)
	dst = conf.encoding.Encode(dst)
	return dst, nil
}

// EncryptTripleCTR uses ctr mode to encrypt data.
// There is no need to specify a padding.
func EncryptTripleCTR(data []byte, key []byte, iv []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, _, err := newTripleBlock(key)
	if err != nil {
		return nil, err
	}

	src := bytes.Clone(data)
	dst := bytes.Clone(src)

	cipher.NewCTR(block, iv).XORKeyStream(dst, src)
	dst = conf.encoding.Encode(dst)
	return dst, nil
}

// DecryptTripleECB uses ecb mode to decrypt data.
// It must specify a padding.
func DecryptTripleECB(data []byte, key []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, blockSize, err := newTripleBlock(key)
	if err != nil {
		return nil, err
	}

	src, err := conf.encoding.Decode(data)
	if err != nil {
		return nil, err
	}

	dst := bytes.Clone(src)

	if len(src)%blockSize != 0 {
		return nil, fmt.Errorf("cryptox/des: decrypt triple ecb len(src) %d %% blockSize %d != 0", len(src), blockSize)
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

// DecryptTripleCBC uses cbc mode to decrypt data.
// It must specify a padding.
func DecryptTripleCBC(data []byte, key []byte, iv []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, blockSize, err := newTripleBlock(key)
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

// DecryptTripleCFB uses cfb mode to decrypt data.
// There is no need to specify a padding.
func DecryptTripleCFB(data []byte, key []byte, iv []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, _, err := newTripleBlock(key)
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

// DecryptTripleOFB uses ofb mode to decrypt data.
// There is no need to specify a padding.
func DecryptTripleOFB(data []byte, key []byte, iv []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, _, err := newTripleBlock(key)
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

// DecryptTripleCTR uses ctr mode to decrypt data.
// There is no need to specify a padding.
func DecryptTripleCTR(data []byte, key []byte, iv []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, _, err := newTripleBlock(key)
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
