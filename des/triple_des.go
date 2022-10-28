// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package des

import "github.com/FishGoddess/cryptox"

// TripleECBEncrypter returns a cryptox.Encrypter using ecb mode.
func TripleECBEncrypter(key []byte, padding cryptox.Padding) cryptox.Encrypter {
	return cryptox.NewEncrypter(cryptox.TripleDES, key, cryptox.EncryptECB, nil, padding)
}

// TripleECBDecrypter returns a cryptox.Decrypter using ecb mode.
func TripleECBDecrypter(key []byte, unPadding cryptox.UnPadding) cryptox.Decrypter {
	return cryptox.NewDecrypter(cryptox.TripleDES, key, cryptox.DecryptECB, nil, unPadding)
}

// TripleCBCEncrypter returns a cryptox.Encrypter using cbc mode.
func TripleCBCEncrypter(key []byte, iv []byte, padding cryptox.Padding) cryptox.Encrypter {
	return cryptox.NewEncrypter(cryptox.TripleDES, key, cryptox.EncryptCBC, iv, padding)
}

// TripleCBCDecrypter returns a cryptox.Decrypter using cbc mode.
func TripleCBCDecrypter(key []byte, iv []byte, unPadding cryptox.UnPadding) cryptox.Decrypter {
	return cryptox.NewDecrypter(cryptox.TripleDES, key, cryptox.DecryptCBC, iv, unPadding)
}

// TripleCFBEncrypter returns a cryptox.Encrypter using cfb mode.
func TripleCFBEncrypter(key []byte, iv []byte, padding cryptox.Padding) cryptox.Encrypter {
	return cryptox.NewEncrypter(cryptox.TripleDES, key, cryptox.EncryptCFB, iv, padding)
}

// TripleCFBDecrypter returns a cryptox.Decrypter using cfb mode.
func TripleCFBDecrypter(key []byte, iv []byte, unPadding cryptox.UnPadding) cryptox.Decrypter {
	return cryptox.NewDecrypter(cryptox.TripleDES, key, cryptox.DecryptCFB, iv, unPadding)
}

// TripleOFBEncrypter returns a cryptox.Encrypter using ofb mode.
func TripleOFBEncrypter(key []byte, iv []byte, padding cryptox.Padding) cryptox.Encrypter {
	return cryptox.NewEncrypter(cryptox.TripleDES, key, cryptox.EncryptOFB, iv, padding)
}

// TripleOFBDecrypter returns a cryptox.Decrypter using ctr mode.
func TripleOFBDecrypter(key []byte, iv []byte, unPadding cryptox.UnPadding) cryptox.Decrypter {
	return cryptox.NewDecrypter(cryptox.TripleDES, key, cryptox.DecryptOFB, iv, unPadding)
}

// TripleCTREncrypter returns a cryptox.Encrypter using ctr mode.
func TripleCTREncrypter(key []byte, iv []byte, padding cryptox.Padding) cryptox.Encrypter {
	return cryptox.NewEncrypter(cryptox.TripleDES, key, cryptox.EncryptCTR, iv, padding)
}

// TripleCTRDecrypter returns a cryptox.Decrypter using ctr mode.
func TripleCTRDecrypter(key []byte, iv []byte, unPadding cryptox.UnPadding) cryptox.Decrypter {
	return cryptox.NewDecrypter(cryptox.TripleDES, key, cryptox.DecryptCTR, iv, unPadding)
}
