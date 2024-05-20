// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package des

import (
	"crypto/cipher"
	"fmt"

	"github.com/FishGoddess/cryptox"
)

func encryptECB(block cipher.Block, padding cryptox.Padding, bs cryptox.Bytes) (cryptox.Bytes, error) {
	blockSize := block.BlockSize()

	src := padding(bs.Clone(), blockSize)
	dst := src.Clone()

	if len(src)%blockSize != 0 {
		return nil, fmt.Errorf("des: encrypt ecb len(src) %d %% blockSize %d != 0", len(src), blockSize)
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

func decryptECB(block cipher.Block, unpadding cryptox.UnPadding, bs cryptox.Bytes) (cryptox.Bytes, error) {
	blockSize := block.BlockSize()

	src := bs
	dst := bs.Clone()

	if len(src)%blockSize != 0 {
		return nil, fmt.Errorf("des: decrypt ecb len(src) %d %% blockSize %d != 0", len(src), blockSize)
	}

	start := 0
	end := blockSize

	for end <= len(src) {
		block.Decrypt(dst[start:end], src[start:end])

		start += blockSize
		end += blockSize
	}

	return unpadding(dst, blockSize)
}

func (d DES) EncryptECB(padding cryptox.Padding, bs cryptox.Bytes) (cryptox.Bytes, error) {
	block, err := d.block, d.err
	if err != nil {
		return nil, err
	}

	return encryptECB(block, padding, bs)
}

func (d DES) DecryptECB(unpadding cryptox.UnPadding, bs cryptox.Bytes) (cryptox.Bytes, error) {
	block, err := d.block, d.err
	if err != nil {
		return nil, err
	}

	return decryptECB(block, unpadding, bs)
}

func (td TripleDES) EncryptECB(padding cryptox.Padding, bs cryptox.Bytes) (cryptox.Bytes, error) {
	block, err := td.block, td.err
	if err != nil {
		return nil, err
	}

	return encryptECB(block, padding, bs)
}

func (td TripleDES) DecryptECB(unpadding cryptox.UnPadding, bs cryptox.Bytes) (cryptox.Bytes, error) {
	block, err := td.block, td.err
	if err != nil {
		return nil, err
	}

	return decryptECB(block, unpadding, bs)
}
