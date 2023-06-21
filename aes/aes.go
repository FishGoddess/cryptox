// Copyright 2023 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package aes

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/FishGoddess/cryptox"
)

// AES packs some function of aes.
type AES struct {
	block cipher.Block
	err   error
}

// New creates a new AES with key.
func New(key cryptox.Bytes) AES {
	block, err := aes.NewCipher(key)

	return AES{
		block: block,
		err:   err,
	}
}
