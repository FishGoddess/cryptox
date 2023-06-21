// Copyright 2023 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package des

import (
	"crypto/cipher"

	"github.com/FishGoddess/cryptox"
)

func encryptCBC(block cipher.Block, padding cryptox.Padding, iv cryptox.Bytes, bs cryptox.Bytes) (cryptox.Bytes, error) {
	src := padding(bs.Clone(), block.BlockSize())
	dst := src.Clone()

	cipher.NewCBCEncrypter(block, iv).CryptBlocks(dst, src)
	return dst, nil
}

func decryptCBC(block cipher.Block, unpadding cryptox.UnPadding, iv cryptox.Bytes, bs cryptox.Bytes) (cryptox.Bytes, error) {
	src := bs
	dst := bs.Clone()

	cipher.NewCBCDecrypter(block, iv).CryptBlocks(dst, src)
	return unpadding(dst, block.BlockSize())
}

func (d DES) EncryptCBC(padding cryptox.Padding, iv cryptox.Bytes, bs cryptox.Bytes) (cryptox.Bytes, error) {
	block, err := d.block, d.err
	if err != nil {
		return nil, err
	}

	return encryptCBC(block, padding, iv, bs)
}

func (d DES) DecryptCBC(unpadding cryptox.UnPadding, iv cryptox.Bytes, bs cryptox.Bytes) (cryptox.Bytes, error) {
	block, err := d.block, d.err
	if err != nil {
		return nil, err
	}

	return decryptCBC(block, unpadding, iv, bs)
}

func (td TripleDES) EncryptCBC(padding cryptox.Padding, iv cryptox.Bytes, bs cryptox.Bytes) (cryptox.Bytes, error) {
	block, err := td.block, td.err
	if err != nil {
		return nil, err
	}

	return encryptCBC(block, padding, iv, bs)
}

func (td TripleDES) DecryptCBC(unpadding cryptox.UnPadding, iv cryptox.Bytes, bs cryptox.Bytes) (cryptox.Bytes, error) {
	block, err := td.block, td.err
	if err != nil {
		return nil, err
	}

	return decryptCBC(block, unpadding, iv, bs)
}
