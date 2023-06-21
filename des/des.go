// Copyright 2023 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package des

import (
	"crypto/cipher"
	"crypto/des"

	"github.com/FishGoddess/cryptox"
)

// DES packs some function of des.
type DES struct {
	block cipher.Block
	err   error
}

// New creates a new DES with key.
func New(key cryptox.Bytes) DES {
	block, err := des.NewCipher(key)

	return DES{
		block: block,
		err:   err,
	}
}

// TripleDES packs some function of 3des.
type TripleDES struct {
	block cipher.Block
	err   error
}

// NewTriple creates a new TripleDES with key.
func NewTriple(key cryptox.Bytes) TripleDES {
	block, err := des.NewTripleDESCipher(key)

	return TripleDES{
		block: block,
		err:   err,
	}
}
