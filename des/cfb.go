// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package des

import (
	"crypto/cipher"

	"github.com/FishGoddess/cryptox"
)

func encryptCFB(block cipher.Block, padding cryptox.Padding, iv cryptox.Bytes, bs cryptox.Bytes) (cryptox.Bytes, error) {
	src := padding(bs.Clone(), block.BlockSize())
	dst := src.Clone()

	cipher.NewCFBEncrypter(block, iv).XORKeyStream(dst, src)
	return dst, nil
}

func decryptCFB(block cipher.Block, unpadding cryptox.UnPadding, iv cryptox.Bytes, bs cryptox.Bytes) (cryptox.Bytes, error) {
	src := bs
	dst := bs.Clone()

	cipher.NewCFBDecrypter(block, iv).XORKeyStream(dst, src)
	return unpadding(dst, block.BlockSize())
}

func (d DES) EncryptCFB(padding cryptox.Padding, iv cryptox.Bytes, bs cryptox.Bytes) (cryptox.Bytes, error) {
	block, err := d.block, d.err
	if err != nil {
		return nil, err
	}

	return encryptCFB(block, padding, iv, bs)
}

func (d DES) DecryptCFB(unpadding cryptox.UnPadding, iv cryptox.Bytes, bs cryptox.Bytes) (cryptox.Bytes, error) {
	block, err := d.block, d.err
	if err != nil {
		return nil, err
	}

	return decryptCFB(block, unpadding, iv, bs)
}

func (td TripleDES) EncryptCFB(padding cryptox.Padding, iv cryptox.Bytes, bs cryptox.Bytes) (cryptox.Bytes, error) {
	block, err := td.block, td.err
	if err != nil {
		return nil, err
	}

	return encryptCFB(block, padding, iv, bs)
}

func (td TripleDES) DecryptCFB(unpadding cryptox.UnPadding, iv cryptox.Bytes, bs cryptox.Bytes) (cryptox.Bytes, error) {
	block, err := td.block, td.err
	if err != nil {
		return nil, err
	}

	return decryptCFB(block, unpadding, iv, bs)
}
