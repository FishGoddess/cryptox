// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package aes

import "github.com/FishGoddess/cryptox"

func ECBEncrypter(key []byte, padding cryptox.Padding) cryptox.Encrypter {
	return cryptox.NewEncrypter(cryptox.AES, key, cryptox.EncryptECB, nil, padding)
}

func ECBDecrypter(key []byte, unPadding cryptox.UnPadding) cryptox.Decrypter {
	return cryptox.NewDecrypter(cryptox.AES, key, cryptox.DecryptECB, nil, unPadding)
}

func CBCEncrypter(key []byte, iv []byte, padding cryptox.Padding) cryptox.Encrypter {
	return cryptox.NewEncrypter(cryptox.AES, key, cryptox.EncryptCBC, iv, padding)
}

func CBCDecrypter(key []byte, iv []byte, unPadding cryptox.UnPadding) cryptox.Decrypter {
	return cryptox.NewDecrypter(cryptox.AES, key, cryptox.DecryptCBC, iv, unPadding)
}

func CFBEncrypter(key []byte, iv []byte, padding cryptox.Padding) cryptox.Encrypter {
	return cryptox.NewEncrypter(cryptox.AES, key, cryptox.EncryptCFB, iv, padding)
}

func CFBDecrypter(key []byte, iv []byte, unPadding cryptox.UnPadding) cryptox.Decrypter {
	return cryptox.NewDecrypter(cryptox.AES, key, cryptox.DecryptCFB, iv, unPadding)
}

func OFBEncrypter(key []byte, iv []byte, padding cryptox.Padding) cryptox.Encrypter {
	return cryptox.NewEncrypter(cryptox.AES, key, cryptox.EncryptOFB, iv, padding)
}

func OFBDecrypter(key []byte, iv []byte, unPadding cryptox.UnPadding) cryptox.Decrypter {
	return cryptox.NewDecrypter(cryptox.AES, key, cryptox.DecryptOFB, iv, unPadding)
}

func CTREncrypter(key []byte, iv []byte, padding cryptox.Padding) cryptox.Encrypter {
	return cryptox.NewEncrypter(cryptox.AES, key, cryptox.EncryptCTR, iv, padding)
}

func CTRDecrypter(key []byte, iv []byte, unPadding cryptox.UnPadding) cryptox.Decrypter {
	return cryptox.NewDecrypter(cryptox.AES, key, cryptox.DecryptCTR, iv, unPadding)
}
