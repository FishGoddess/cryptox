// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package aes

import "github.com/FishGoddess/cryptox"

func EncryptECB(key []byte, padding cryptox.Padding) cryptox.Encryptor {
	return cryptox.NewEncryptor(cryptox.AES, key, cryptox.EncryptECB, nil, padding)
}

func DecryptECB(key []byte, unPadding cryptox.UnPadding) cryptox.Decryptor {
	return cryptox.NewDecryptor(cryptox.AES, key, cryptox.DecryptECB, nil, unPadding)
}

func EncryptCBC(key []byte, iv []byte, padding cryptox.Padding) cryptox.Encryptor {
	return cryptox.NewEncryptor(cryptox.AES, key, cryptox.EncryptCBC, iv, padding)
}

func DecryptCBC(key []byte, iv []byte, unPadding cryptox.UnPadding) cryptox.Decryptor {
	return cryptox.NewDecryptor(cryptox.AES, key, cryptox.DecryptCBC, iv, unPadding)
}

func EncryptCFB(key []byte, iv []byte, padding cryptox.Padding) cryptox.Encryptor {
	return cryptox.NewEncryptor(cryptox.AES, key, cryptox.EncryptCFB, iv, padding)
}

func DecryptCFB(key []byte, iv []byte, unPadding cryptox.UnPadding) cryptox.Decryptor {
	return cryptox.NewDecryptor(cryptox.AES, key, cryptox.DecryptCFB, iv, unPadding)
}

func EncryptOFB(key []byte, iv []byte, padding cryptox.Padding) cryptox.Encryptor {
	return cryptox.NewEncryptor(cryptox.AES, key, cryptox.EncryptOFB, iv, padding)
}

func DecryptOFB(key []byte, iv []byte, unPadding cryptox.UnPadding) cryptox.Decryptor {
	return cryptox.NewDecryptor(cryptox.AES, key, cryptox.DecryptOFB, iv, unPadding)
}

func EncryptCTR(key []byte, iv []byte, padding cryptox.Padding) cryptox.Encryptor {
	return cryptox.NewEncryptor(cryptox.AES, key, cryptox.EncryptCTR, iv, padding)
}

func DecryptCTR(key []byte, iv []byte, unPadding cryptox.UnPadding) cryptox.Decryptor {
	return cryptox.NewDecryptor(cryptox.AES, key, cryptox.DecryptCTR, iv, unPadding)
}
