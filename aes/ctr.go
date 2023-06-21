// Copyright 2023 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package aes

import (
	"crypto/cipher"

	"github.com/FishGoddess/cryptox"
)

func encryptCTR(block cipher.Block, padding cryptox.Padding, iv cryptox.Bytes, bs cryptox.Bytes) (cryptox.Bytes, error) {
	src := padding(bs.Clone(), block.BlockSize())
	dst := src.Clone()

	cipher.NewCTR(block, iv).XORKeyStream(dst, src)
	return dst, nil
}

func decryptCTR(block cipher.Block, unpadding cryptox.UnPadding, iv cryptox.Bytes, bs cryptox.Bytes) (cryptox.Bytes, error) {
	src := bs
	dst := bs.Clone()

	cipher.NewCTR(block, iv).XORKeyStream(dst, src)
	return unpadding(dst, block.BlockSize())
}

func (a AES) EncryptCTR(padding cryptox.Padding, iv cryptox.Bytes, bs cryptox.Bytes) (cryptox.Bytes, error) {
	block, err := a.block, a.err
	if err != nil {
		return nil, err
	}

	return encryptCTR(block, padding, iv, bs)
}

func (a AES) DecryptCTR(unpadding cryptox.UnPadding, iv cryptox.Bytes, bs cryptox.Bytes) (cryptox.Bytes, error) {
	block, err := a.block, a.err
	if err != nil {
		return nil, err
	}

	return decryptCTR(block, unpadding, iv, bs)
}
