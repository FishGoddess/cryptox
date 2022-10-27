// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package des

import (
	"crypto/aes"

	"github.com/FishGoddess/cryptox"
	"github.com/FishGoddess/cryptox/base64"
	"github.com/FishGoddess/cryptox/hex"
	"github.com/FishGoddess/cryptox/pkg/bytes"
)

type AES struct {
	key []byte
}

func New(key []byte) *AES {
	return &AES{
		key: key,
	}
}

func (a *AES) EncryptECB(plain []byte, padder cryptox.Padder) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}

	plain = bytes.Copy(plain)

	ecb := cryptox.NewEncryptECB(block, padder)
	return ecb.Encrypt(plain)
}

func (a *AES) EncryptECBHex(plain []byte, padder cryptox.Padder) (string, error) {
	crypted, err := a.EncryptECB(plain, padder)
	if err != nil {
		return "", err
	}

	return hex.Encode(crypted), nil
}

func (a *AES) EncryptECBBase64(plain []byte, padder cryptox.Padder) (string, error) {
	crypted, err := a.EncryptECB(plain, padder)
	if err != nil {
		return "", err
	}

	return base64.Encode(crypted), nil
}

func (a *AES) DecryptECB(crypted []byte, padder cryptox.Padder) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}

	crypted = bytes.Copy(crypted)

	ecb := cryptox.NewDecryptECB(block, padder)
	return ecb.Decrypt(crypted)
}

func (a *AES) DecryptECBHex(crypted string, padder cryptox.Padder) ([]byte, error) {
	decoded, err := hex.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return a.DecryptECB(decoded, padder)
}

func (a *AES) DecryptECBBase64(crypted string, padder cryptox.Padder) ([]byte, error) {
	decoded, err := base64.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return a.DecryptECB(decoded, padder)
}

func (a *AES) EncryptCBC(plain []byte, iv []byte, padder cryptox.Padder) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}

	plain = bytes.Copy(plain)

	cbc := cryptox.NewEncryptCBC(block, iv, padder)
	return cbc.Encrypt(plain)
}

func (a *AES) EncryptCBCHex(plain []byte, iv []byte, padder cryptox.Padder) (string, error) {
	crypted, err := a.EncryptCBC(plain, iv, padder)
	if err != nil {
		return "", err
	}

	return hex.Encode(crypted), nil
}

func (a *AES) EncryptCBCBase64(plain []byte, iv []byte, padder cryptox.Padder) (string, error) {
	crypted, err := a.EncryptCBC(plain, iv, padder)
	if err != nil {
		return "", err
	}

	return base64.Encode(crypted), nil
}

func (a *AES) DecryptCBC(crypted []byte, iv []byte, padder cryptox.Padder) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}

	crypted = bytes.Copy(crypted)

	cbc := cryptox.NewDecryptCBC(block, iv, padder)
	return cbc.Decrypt(crypted)
}

func (a *AES) DecryptCBCHex(crypted string, iv []byte, padder cryptox.Padder) ([]byte, error) {
	decoded, err := hex.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return a.DecryptCBC(decoded, iv, padder)
}

func (a *AES) DecryptCBCBase64(crypted string, iv []byte, padder cryptox.Padder) ([]byte, error) {
	decoded, err := base64.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return a.DecryptCBC(decoded, iv, padder)
}

func (a *AES) EncryptCFB(plain []byte, iv []byte, padder cryptox.Padder) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}

	plain = bytes.Copy(plain)

	cfb := cryptox.NewEncryptCFB(block, iv, padder)
	return cfb.Encrypt(plain)
}

func (a *AES) EncryptCFBHex(plain []byte, iv []byte, padder cryptox.Padder) (string, error) {
	crypted, err := a.EncryptCFB(plain, iv, padder)
	if err != nil {
		return "", err
	}

	return hex.Encode(crypted), nil
}

func (a *AES) EncryptCFBBase64(plain []byte, iv []byte, padder cryptox.Padder) (string, error) {
	crypted, err := a.EncryptCFB(plain, iv, padder)
	if err != nil {
		return "", err
	}

	return base64.Encode(crypted), nil
}

func (a *AES) DecryptCFB(crypted []byte, iv []byte, padder cryptox.Padder) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}

	crypted = bytes.Copy(crypted)

	cfb := cryptox.NewDecryptCFB(block, iv, padder)
	return cfb.Decrypt(crypted)
}

func (a *AES) DecryptCFBHex(crypted string, iv []byte, padder cryptox.Padder) ([]byte, error) {
	decoded, err := hex.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return a.DecryptCFB(decoded, iv, padder)
}

func (a *AES) DecryptCFBBase64(crypted string, iv []byte, padder cryptox.Padder) ([]byte, error) {
	decoded, err := base64.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return a.DecryptCFB(decoded, iv, padder)
}

func (a *AES) EncryptOFB(plain []byte, iv []byte, padder cryptox.Padder) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}

	plain = bytes.Copy(plain)

	cbc := cryptox.NewEncryptOFB(block, iv, padder)
	return cbc.Encrypt(plain)
}

func (a *AES) EncryptOFBHex(plain []byte, iv []byte, padder cryptox.Padder) (string, error) {
	crypted, err := a.EncryptOFB(plain, iv, padder)
	if err != nil {
		return "", err
	}

	return hex.Encode(crypted), nil
}

func (a *AES) EncryptOFBBase64(plain []byte, iv []byte, padder cryptox.Padder) (string, error) {
	crypted, err := a.EncryptOFB(plain, iv, padder)
	if err != nil {
		return "", err
	}

	return base64.Encode(crypted), nil
}

func (a *AES) DecryptOFB(crypted []byte, iv []byte, padder cryptox.Padder) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}

	crypted = bytes.Copy(crypted)

	cbc := cryptox.NewDecryptOFB(block, iv, padder)
	return cbc.Decrypt(crypted)
}

func (a *AES) DecryptOFBHex(crypted string, iv []byte, padder cryptox.Padder) ([]byte, error) {
	decoded, err := hex.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return a.DecryptOFB(decoded, iv, padder)
}

func (a *AES) DecryptOFBBase64(crypted string, iv []byte, padder cryptox.Padder) ([]byte, error) {
	decoded, err := base64.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return a.DecryptOFB(decoded, iv, padder)
}

func (a *AES) EncryptCTR(plain []byte, iv []byte, padder cryptox.Padder) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}

	plain = bytes.Copy(plain)

	cbc := cryptox.NewEncryptCTR(block, iv, padder)
	return cbc.Encrypt(plain)
}

func (a *AES) EncryptCTRHex(plain []byte, iv []byte, padder cryptox.Padder) (string, error) {
	crypted, err := a.EncryptCTR(plain, iv, padder)
	if err != nil {
		return "", err
	}

	return hex.Encode(crypted), nil
}

func (a *AES) EncryptCTRBase64(plain []byte, iv []byte, padder cryptox.Padder) (string, error) {
	crypted, err := a.EncryptCTR(plain, iv, padder)
	if err != nil {
		return "", err
	}

	return base64.Encode(crypted), nil
}

func (a *AES) DecryptCTR(crypted []byte, iv []byte, padder cryptox.Padder) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}

	crypted = bytes.Copy(crypted)

	cbc := cryptox.NewDecryptCTR(block, iv, padder)
	return cbc.Decrypt(crypted)
}

func (a *AES) DecryptCTRHex(crypted string, iv []byte, padder cryptox.Padder) ([]byte, error) {
	decoded, err := hex.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return a.DecryptCTR(decoded, iv, padder)
}

func (a *AES) DecryptCTRBase64(crypted string, iv []byte, padder cryptox.Padder) ([]byte, error) {
	decoded, err := base64.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return a.DecryptCTR(decoded, iv, padder)
}
