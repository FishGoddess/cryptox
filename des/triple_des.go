// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package des

import "github.com/FishGoddess/cryptox"

func TripleECBEncrypter(key []byte, padding cryptox.Padding) cryptox.Encrypter {
	return cryptox.NewEncrypter(cryptox.TripleDES, key, cryptox.EncryptECB, nil, padding)
}

func TripleECBDecrypter(key []byte, unPadding cryptox.UnPadding) cryptox.Decrypter {
	return cryptox.NewDecrypter(cryptox.TripleDES, key, cryptox.DecryptECB, nil, unPadding)
}

func TripleCBCEncrypter(key []byte, iv []byte, padding cryptox.Padding) cryptox.Encrypter {
	return cryptox.NewEncrypter(cryptox.TripleDES, key, cryptox.EncryptCBC, iv, padding)
}

func TripleCBCDecrypter(key []byte, iv []byte, unPadding cryptox.UnPadding) cryptox.Decrypter {
	return cryptox.NewDecrypter(cryptox.TripleDES, key, cryptox.DecryptCBC, iv, unPadding)
}

func TripleCFBEncrypter(key []byte, iv []byte, padding cryptox.Padding) cryptox.Encrypter {
	return cryptox.NewEncrypter(cryptox.TripleDES, key, cryptox.EncryptCFB, iv, padding)
}

func TripleCFBDecrypter(key []byte, iv []byte, unPadding cryptox.UnPadding) cryptox.Decrypter {
	return cryptox.NewDecrypter(cryptox.TripleDES, key, cryptox.DecryptCFB, iv, unPadding)
}

func TripleOFBEncrypter(key []byte, iv []byte, padding cryptox.Padding) cryptox.Encrypter {
	return cryptox.NewEncrypter(cryptox.TripleDES, key, cryptox.EncryptOFB, iv, padding)
}

func TripleOFBDecrypter(key []byte, iv []byte, unPadding cryptox.UnPadding) cryptox.Decrypter {
	return cryptox.NewDecrypter(cryptox.TripleDES, key, cryptox.DecryptOFB, iv, unPadding)
}

func TripleCTREncrypter(key []byte, iv []byte, padding cryptox.Padding) cryptox.Encrypter {
	return cryptox.NewEncrypter(cryptox.TripleDES, key, cryptox.EncryptCTR, iv, padding)
}

func TripleCTRDecrypter(key []byte, iv []byte, unPadding cryptox.UnPadding) cryptox.Decrypter {
	return cryptox.NewDecrypter(cryptox.TripleDES, key, cryptox.DecryptCTR, iv, unPadding)
}
