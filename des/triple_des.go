// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package des

import (
	"crypto/des"

	"github.com/FishGoddess/cryptox"
	"github.com/FishGoddess/cryptox/base64"
	"github.com/FishGoddess/cryptox/hex"
	"github.com/FishGoddess/cryptox/pkg/bytes"
)

type TripleDES struct {
	key []byte
}

func NewTriple(key []byte) *TripleDES {
	return &TripleDES{
		key: key,
	}
}

func (d *TripleDES) EncryptECB(plain []byte, padder cryptox.Padder) ([]byte, error) {
	block, err := des.NewTripleDESCipher(d.key)
	if err != nil {
		return nil, err
	}

	plain = bytes.Copy(plain)

	ecb := cryptox.NewEncryptECB(block, padder)
	return ecb.Encrypt(plain)
}

func (d *TripleDES) EncryptECBHex(plain []byte, padder cryptox.Padder) (string, error) {
	crypted, err := d.EncryptECB(plain, padder)
	if err != nil {
		return "", err
	}

	return hex.Encode(crypted), nil
}

func (d *TripleDES) EncryptECBBase64(plain []byte, padder cryptox.Padder) (string, error) {
	crypted, err := d.EncryptECB(plain, padder)
	if err != nil {
		return "", err
	}

	return base64.Encode(crypted), nil
}

func (d *TripleDES) DecryptECB(crypted []byte, padder cryptox.Padder) ([]byte, error) {
	block, err := des.NewTripleDESCipher(d.key)
	if err != nil {
		return nil, err
	}

	crypted = bytes.Copy(crypted)

	ecb := cryptox.NewDecryptECB(block, padder)
	return ecb.Decrypt(crypted)
}

func (d *TripleDES) DecryptECBHex(crypted string, padder cryptox.Padder) ([]byte, error) {
	decoded, err := hex.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return d.DecryptECB(decoded, padder)
}

func (d *TripleDES) DecryptECBBase64(crypted string, padder cryptox.Padder) ([]byte, error) {
	decoded, err := base64.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return d.DecryptECB(decoded, padder)
}

func (d *TripleDES) EncryptCBC(plain []byte, iv []byte, padder cryptox.Padder) ([]byte, error) {
	block, err := des.NewTripleDESCipher(d.key)
	if err != nil {
		return nil, err
	}

	plain = bytes.Copy(plain)

	cbc := cryptox.NewEncryptCBC(block, iv, padder)
	return cbc.Encrypt(plain)
}

func (d *TripleDES) EncryptCBCHex(plain []byte, iv []byte, padder cryptox.Padder) (string, error) {
	crypted, err := d.EncryptCBC(plain, iv, padder)
	if err != nil {
		return "", err
	}

	return hex.Encode(crypted), nil
}

func (d *TripleDES) EncryptCBCBase64(plain []byte, iv []byte, padder cryptox.Padder) (string, error) {
	crypted, err := d.EncryptCBC(plain, iv, padder)
	if err != nil {
		return "", err
	}

	return base64.Encode(crypted), nil
}

func (d *TripleDES) DecryptCBC(crypted []byte, iv []byte, padder cryptox.Padder) ([]byte, error) {
	block, err := des.NewTripleDESCipher(d.key)
	if err != nil {
		return nil, err
	}

	crypted = bytes.Copy(crypted)

	cbc := cryptox.NewDecryptCBC(block, iv, padder)
	return cbc.Decrypt(crypted)
}

func (d *TripleDES) DecryptCBCHex(crypted string, iv []byte, padder cryptox.Padder) ([]byte, error) {
	decoded, err := hex.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return d.DecryptCBC(decoded, iv, padder)
}

func (d *TripleDES) DecryptCBCBase64(crypted string, iv []byte, padder cryptox.Padder) ([]byte, error) {
	decoded, err := base64.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return d.DecryptCBC(decoded, iv, padder)
}

func (d *TripleDES) EncryptCFB(plain []byte, iv []byte, padder cryptox.Padder) ([]byte, error) {
	block, err := des.NewTripleDESCipher(d.key)
	if err != nil {
		return nil, err
	}

	plain = bytes.Copy(plain)

	cfb := cryptox.NewEncryptCFB(block, iv, padder)
	return cfb.Encrypt(plain)
}

func (d *TripleDES) EncryptCFBHex(plain []byte, iv []byte, padder cryptox.Padder) (string, error) {
	crypted, err := d.EncryptCFB(plain, iv, padder)
	if err != nil {
		return "", err
	}

	return hex.Encode(crypted), nil
}

func (d *TripleDES) EncryptCFBBase64(plain []byte, iv []byte, padder cryptox.Padder) (string, error) {
	crypted, err := d.EncryptCFB(plain, iv, padder)
	if err != nil {
		return "", err
	}

	return base64.Encode(crypted), nil
}

func (d *TripleDES) DecryptCFB(crypted []byte, iv []byte, padder cryptox.Padder) ([]byte, error) {
	block, err := des.NewTripleDESCipher(d.key)
	if err != nil {
		return nil, err
	}

	crypted = bytes.Copy(crypted)

	cfb := cryptox.NewDecryptCFB(block, iv, padder)
	return cfb.Decrypt(crypted)
}

func (d *TripleDES) DecryptCFBHex(crypted string, iv []byte, padder cryptox.Padder) ([]byte, error) {
	decoded, err := hex.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return d.DecryptCFB(decoded, iv, padder)
}

func (d *TripleDES) DecryptCFBBase64(crypted string, iv []byte, padder cryptox.Padder) ([]byte, error) {
	decoded, err := base64.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return d.DecryptCFB(decoded, iv, padder)
}

func (d *TripleDES) EncryptOFB(plain []byte, iv []byte, padder cryptox.Padder) ([]byte, error) {
	block, err := des.NewTripleDESCipher(d.key)
	if err != nil {
		return nil, err
	}

	plain = bytes.Copy(plain)

	cbc := cryptox.NewEncryptOFB(block, iv, padder)
	return cbc.Encrypt(plain)
}

func (d *TripleDES) EncryptOFBHex(plain []byte, iv []byte, padder cryptox.Padder) (string, error) {
	crypted, err := d.EncryptOFB(plain, iv, padder)
	if err != nil {
		return "", err
	}

	return hex.Encode(crypted), nil
}

func (d *TripleDES) EncryptOFBBase64(plain []byte, iv []byte, padder cryptox.Padder) (string, error) {
	crypted, err := d.EncryptOFB(plain, iv, padder)
	if err != nil {
		return "", err
	}

	return base64.Encode(crypted), nil
}

func (d *TripleDES) DecryptOFB(crypted []byte, iv []byte, padder cryptox.Padder) ([]byte, error) {
	block, err := des.NewTripleDESCipher(d.key)
	if err != nil {
		return nil, err
	}

	crypted = bytes.Copy(crypted)

	cbc := cryptox.NewDecryptOFB(block, iv, padder)
	return cbc.Decrypt(crypted)
}

func (d *TripleDES) DecryptOFBHex(crypted string, iv []byte, padder cryptox.Padder) ([]byte, error) {
	decoded, err := hex.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return d.DecryptOFB(decoded, iv, padder)
}

func (d *TripleDES) DecryptOFBBase64(crypted string, iv []byte, padder cryptox.Padder) ([]byte, error) {
	decoded, err := base64.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return d.DecryptOFB(decoded, iv, padder)
}

func (d *TripleDES) EncryptCTR(plain []byte, iv []byte, padder cryptox.Padder) ([]byte, error) {
	block, err := des.NewTripleDESCipher(d.key)
	if err != nil {
		return nil, err
	}

	plain = bytes.Copy(plain)

	cbc := cryptox.NewEncryptCTR(block, iv, padder)
	return cbc.Encrypt(plain)
}

func (d *TripleDES) EncryptCTRHex(plain []byte, iv []byte, padder cryptox.Padder) (string, error) {
	crypted, err := d.EncryptCTR(plain, iv, padder)
	if err != nil {
		return "", err
	}

	return hex.Encode(crypted), nil
}

func (d *TripleDES) EncryptCTRBase64(plain []byte, iv []byte, padder cryptox.Padder) (string, error) {
	crypted, err := d.EncryptCTR(plain, iv, padder)
	if err != nil {
		return "", err
	}

	return base64.Encode(crypted), nil
}

func (d *TripleDES) DecryptCTR(crypted []byte, iv []byte, padder cryptox.Padder) ([]byte, error) {
	block, err := des.NewTripleDESCipher(d.key)
	if err != nil {
		return nil, err
	}

	crypted = bytes.Copy(crypted)

	cbc := cryptox.NewDecryptCTR(block, iv, padder)
	return cbc.Decrypt(crypted)
}

func (d *TripleDES) DecryptCTRHex(crypted string, iv []byte, padder cryptox.Padder) ([]byte, error) {
	decoded, err := hex.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return d.DecryptCTR(decoded, iv, padder)
}

func (d *TripleDES) DecryptCTRBase64(crypted string, iv []byte, padder cryptox.Padder) ([]byte, error) {
	decoded, err := base64.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return d.DecryptCTR(decoded, iv, padder)
}
