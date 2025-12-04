// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func newBlock(key []byte) (cipher.Block, int, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, 0, err
	}

	blockSize := block.BlockSize()
	return block, blockSize, nil
}

// EncryptECB uses ecb mode to encrypt bs.
// It must specify a padding.
func EncryptECB(bs []byte, key []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, blockSize, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src := bytes.Clone(bs)
	src = conf.padding.Pad(src, blockSize)
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

	dst = conf.encoding.Encode(dst)
	return dst, nil
}

// EncryptCBC uses cbc mode to encrypt bs.
// It must specify a padding.
func EncryptCBC(bs []byte, key []byte, iv []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, blockSize, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src := bytes.Clone(bs)
	src = conf.padding.Pad(src, blockSize)
	dst := bytes.Clone(src)

	cipher.NewCBCEncrypter(block, iv).CryptBlocks(dst, src)
	dst = conf.encoding.Encode(dst)
	return dst, nil
}

// EncryptCFB uses cfb mode to encrypt bs.
// There is no need to specify a padding.
func EncryptCFB(bs []byte, key []byte, iv []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, _, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src := bytes.Clone(bs)
	dst := bytes.Clone(src)

	cipher.NewCFBEncrypter(block, iv).XORKeyStream(dst, src)
	dst = conf.encoding.Encode(dst)
	return dst, nil
}

// EncryptOFB uses ofb mode to encrypt bs.
// There is no need to specify a padding.
func EncryptOFB(bs []byte, key []byte, iv []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, _, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src := bytes.Clone(bs)
	dst := bytes.Clone(src)

	cipher.NewOFB(block, iv).XORKeyStream(dst, src)
	dst = conf.encoding.Encode(dst)
	return dst, nil
}

// EncryptCTR uses ctr mode to encrypt bs.
// There is no need to specify a padding.
func EncryptCTR(bs []byte, key []byte, iv []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, _, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src := bytes.Clone(bs)
	dst := bytes.Clone(src)

	cipher.NewCTR(block, iv).XORKeyStream(dst, src)
	dst = conf.encoding.Encode(dst)
	return dst, nil
}

// EncryptGCM uses gcm mode to encrypt bs.
// There is no need to specify a padding.
func EncryptGCM(bs []byte, key []byte, nonce []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, _, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src := bs
	dst := bytes.Clone(src)
	dst = dst[:0]

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	dst = gcm.Seal(dst, nonce, src, conf.additional)
	dst = conf.encoding.Encode(dst)
	return dst, nil
}

// DecryptECB uses ecb mode to decrypt bs.
// It must specify a padding.
func DecryptECB(bs []byte, key []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, blockSize, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src, err := conf.encoding.Decode(bs)
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

	return conf.padding.Unpad(dst, blockSize)
}

// DecryptCBC uses cbc mode to decrypt bs.
// It must specify a padding.
func DecryptCBC(bs []byte, key []byte, iv []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, blockSize, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src, err := conf.encoding.Decode(bs)
	if err != nil {
		return nil, err
	}

	dst := bytes.Clone(src)

	cipher.NewCBCDecrypter(block, iv).CryptBlocks(dst, src)
	return conf.padding.Unpad(dst, blockSize)
}

// DecryptCFB uses cfb mode to decrypt bs.
// There is no need to specify a padding.
func DecryptCFB(bs []byte, key []byte, iv []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, _, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src, err := conf.encoding.Decode(bs)
	if err != nil {
		return nil, err
	}

	dst := bytes.Clone(src)

	cipher.NewCFBDecrypter(block, iv).XORKeyStream(dst, src)
	return dst, nil
}

// DecryptOFB uses ofb mode to decrypt bs.
// There is no need to specify a padding.
func DecryptOFB(bs []byte, key []byte, iv []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, _, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src, err := conf.encoding.Decode(bs)
	if err != nil {
		return nil, err
	}

	dst := bytes.Clone(src)

	cipher.NewOFB(block, iv).XORKeyStream(dst, src)
	return dst, nil
}

// DecryptCTR uses ctr mode to decrypt bs.
// There is no need to specify a padding.
func DecryptCTR(bs []byte, key []byte, iv []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, _, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src, err := conf.encoding.Decode(bs)
	if err != nil {
		return nil, err
	}

	dst := bytes.Clone(src)

	cipher.NewCTR(block, iv).XORKeyStream(dst, src)
	return dst, nil
}

// DecryptGCM uses gcm mode to decrypt bs.
// There is no need to specify a padding.
func DecryptGCM(bs []byte, key []byte, nonce []byte, opts ...Option) ([]byte, error) {
	conf := newConfig().Apply(opts...)

	block, _, err := newBlock(key)
	if err != nil {
		return nil, err
	}

	src, err := conf.encoding.Decode(bs)
	if err != nil {
		return nil, err
	}

	dst := bytes.Clone(src)
	dst = dst[:0]

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(dst, nonce, src, conf.additional)
}
