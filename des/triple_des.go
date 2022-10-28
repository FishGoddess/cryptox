// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package des

import "github.com/FishGoddess/cryptox"

func EncryptTripleECB(key []byte, padding cryptox.Padding) cryptox.Encryptor {
	return cryptox.NewEncryptor(cryptox.TripleDES, key, cryptox.EncryptECB, nil, padding)
}

func DecryptTripleECB(key []byte, unPadding cryptox.UnPadding) cryptox.Decryptor {
	return cryptox.NewDecryptor(cryptox.TripleDES, key, cryptox.DecryptECB, nil, unPadding)
}

func EncryptTripleCBC(key []byte, iv []byte, padding cryptox.Padding) cryptox.Encryptor {
	return cryptox.NewEncryptor(cryptox.TripleDES, key, cryptox.EncryptCBC, iv, padding)
}

func DecryptTripleCBC(key []byte, iv []byte, unPadding cryptox.UnPadding) cryptox.Decryptor {
	return cryptox.NewDecryptor(cryptox.TripleDES, key, cryptox.DecryptCBC, iv, unPadding)
}

func EncryptTripleCFB(key []byte, iv []byte, padding cryptox.Padding) cryptox.Encryptor {
	return cryptox.NewEncryptor(cryptox.TripleDES, key, cryptox.EncryptCFB, iv, padding)
}

func DecryptTripleCFB(key []byte, iv []byte, unPadding cryptox.UnPadding) cryptox.Decryptor {
	return cryptox.NewDecryptor(cryptox.TripleDES, key, cryptox.DecryptCFB, iv, unPadding)
}

func EncryptTripleOFB(key []byte, iv []byte, padding cryptox.Padding) cryptox.Encryptor {
	return cryptox.NewEncryptor(cryptox.TripleDES, key, cryptox.EncryptOFB, iv, padding)
}

func DecryptTripleOFB(key []byte, iv []byte, unPadding cryptox.UnPadding) cryptox.Decryptor {
	return cryptox.NewDecryptor(cryptox.TripleDES, key, cryptox.DecryptOFB, iv, unPadding)
}

func EncryptTripleCTR(key []byte, iv []byte, padding cryptox.Padding) cryptox.Encryptor {
	return cryptox.NewEncryptor(cryptox.TripleDES, key, cryptox.EncryptCTR, iv, padding)
}

func DecryptTripleCTR(key []byte, iv []byte, unPadding cryptox.UnPadding) cryptox.Decryptor {
	return cryptox.NewDecryptor(cryptox.TripleDES, key, cryptox.DecryptCTR, iv, unPadding)
}
