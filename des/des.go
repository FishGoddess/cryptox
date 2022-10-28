// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package des

import "github.com/FishGoddess/cryptox"

// ECBEncrypter returns a cryptox.Encrypter using ecb mode.
func ECBEncrypter(key []byte, padding cryptox.Padding) cryptox.Encrypter {
	return cryptox.NewEncrypter(cryptox.DES, key, cryptox.EncryptECB, nil, padding)
}

// ECBDecrypter returns a cryptox.Decrypter using ecb mode.
func ECBDecrypter(key []byte, unPadding cryptox.UnPadding) cryptox.Decrypter {
	return cryptox.NewDecrypter(cryptox.DES, key, cryptox.DecryptECB, nil, unPadding)
}

// CBCEncrypter returns a cryptox.Encrypter using cbc mode.
func CBCEncrypter(key []byte, iv []byte, padding cryptox.Padding) cryptox.Encrypter {
	return cryptox.NewEncrypter(cryptox.DES, key, cryptox.EncryptCBC, iv, padding)
}

// CBCDecrypter returns a cryptox.Decrypter using cbc mode.
func CBCDecrypter(key []byte, iv []byte, unPadding cryptox.UnPadding) cryptox.Decrypter {
	return cryptox.NewDecrypter(cryptox.DES, key, cryptox.DecryptCBC, iv, unPadding)
}

// CFBEncrypter returns a cryptox.Encrypter using cfb mode.
func CFBEncrypter(key []byte, iv []byte, padding cryptox.Padding) cryptox.Encrypter {
	return cryptox.NewEncrypter(cryptox.DES, key, cryptox.EncryptCFB, iv, padding)
}

// CFBDecrypter returns a cryptox.Decrypter using cfb mode.
func CFBDecrypter(key []byte, iv []byte, unPadding cryptox.UnPadding) cryptox.Decrypter {
	return cryptox.NewDecrypter(cryptox.DES, key, cryptox.DecryptCFB, iv, unPadding)
}

// OFBEncrypter returns a cryptox.Encrypter using ofb mode.
func OFBEncrypter(key []byte, iv []byte, padding cryptox.Padding) cryptox.Encrypter {
	return cryptox.NewEncrypter(cryptox.DES, key, cryptox.EncryptOFB, iv, padding)
}

// OFBDecrypter returns a cryptox.Decrypter using ofb mode.
func OFBDecrypter(key []byte, iv []byte, unPadding cryptox.UnPadding) cryptox.Decrypter {
	return cryptox.NewDecrypter(cryptox.DES, key, cryptox.DecryptOFB, iv, unPadding)
}

// CTREncrypter returns a cryptox.Encrypter using ctr mode.
func CTREncrypter(key []byte, iv []byte, padding cryptox.Padding) cryptox.Encrypter {
	return cryptox.NewEncrypter(cryptox.DES, key, cryptox.EncryptCTR, iv, padding)
}

// CTRDecrypter returns a cryptox.Decrypter using ctr mode.
func CTRDecrypter(key []byte, iv []byte, unPadding cryptox.UnPadding) cryptox.Decrypter {
	return cryptox.NewDecrypter(cryptox.DES, key, cryptox.DecryptCTR, iv, unPadding)
}
