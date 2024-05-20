// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package aes

import (
	"crypto/cipher"
	"fmt"

	"github.com/FishGoddess/cryptox"
)

const (
	gcmStandardNonceSize = 12
)

// GenerateGCMNonce generates a nonce for gcm.
func GenerateGCMNonce() (cryptox.Bytes, error) {
	nonce, err := cryptox.GenerateBytes(gcmStandardNonceSize)
	if err != nil {
		return nil, err
	}

	if len(nonce) != gcmStandardNonceSize {
		return nil, fmt.Errorf("aes: len(nonce) %d is wrong", len(nonce))
	}

	return nonce, nil
}

func encryptGCM(block cipher.Block, nonce cryptox.Bytes, bs cryptox.Bytes, additional cryptox.Bytes) (cryptox.Bytes, error) {
	src := bs.Clone()
	dst := src[:0]

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	dst = gcm.Seal(dst, nonce, src, additional)
	return dst, nil
}

func decryptGCM(block cipher.Block, nonce cryptox.Bytes, bs cryptox.Bytes, additional cryptox.Bytes) (cryptox.Bytes, error) {
	src := bs.Clone()
	dst := src[:0]

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	dst, err = gcm.Open(dst, nonce, src, additional)
	return dst, err
}

// EncryptGCM uses gcm mode to encrypt bs.
// NOTICE: This is an experimental function, and we haven't tested it enough yet, so be careful when using it.
func (a AES) EncryptGCM(nonce cryptox.Bytes, bs cryptox.Bytes, additional cryptox.Bytes) (cryptox.Bytes, error) {
	block, err := a.block, a.err
	if err != nil {
		return nil, err
	}

	return encryptGCM(block, nonce, bs, additional)
}

// DecryptGCM uses gcm mode to decrypt bs.
// NOTICE: This is an experimental function, and we haven't tested it enough yet, so be careful when using it.
func (a AES) DecryptGCM(nonce cryptox.Bytes, bs cryptox.Bytes, additional cryptox.Bytes) (cryptox.Bytes, error) {
	block, err := a.block, a.err
	if err != nil {
		return nil, err
	}

	return decryptGCM(block, nonce, bs, additional)
}
