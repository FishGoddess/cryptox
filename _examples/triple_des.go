// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/FishGoddess/cryptox"
	"github.com/FishGoddess/cryptox/des"
)

func main() {
	// As you know, key is necessary in 3des.
	// However, not all modes need iv, such as ecb.
	key := []byte("123456788765432112345678")
	iv := []byte("87654321")

	plain := []byte("你好，世界")
	fmt.Println("plain:", string(plain))

	// We use cbc mode and pkcs7 padding to encrypt data.
	// Of course, you can choose ecb/cbc/cfb/ofb/ctr if you want.
	// Also, you can choose no/zero/pkcs5/pkcs7 to padding data.
	crypted, err := des.TripleCBCEncrypter(key, iv, cryptox.PaddingPKCS7).Encrypt(plain)
	if err != nil {
		panic(err)
	}

	// Use EncryptHex if you want your output is hex.
	cryptedHex, err := des.TripleCBCEncrypter(key, iv, cryptox.PaddingPKCS7).EncryptHex(plain)
	if err != nil {
		panic(err)
	}

	// Use EncryptBase64 if you want your output is base64.
	cryptedBase64, err := des.TripleCBCEncrypter(key, iv, cryptox.PaddingPKCS7).EncryptBase64(plain)
	if err != nil {
		panic(err)
	}

	fmt.Println("crypted:", crypted)
	fmt.Println("cryptedHex:", cryptedHex)
	fmt.Println("cryptedBase64:", cryptedBase64)

	// We use cbc mode and pkcs7 unPadding to decrypt data.
	// Of course, you can choose ecb/cbc/cfb/ofb/ctr if you want.
	// Also, you can choose no/zero/pkcs5/pkcs7 to unPadding data.
	plain, err = des.TripleCBCDecrypter(key, iv, cryptox.UnPaddingPKCS7).Decrypt(crypted)
	if err != nil {
		panic(err)
	}

	// Use DecryptHex if your input is hex.
	plain, err = des.TripleCBCDecrypter(key, iv, cryptox.UnPaddingPKCS7).DecryptHex(cryptedHex)
	if err != nil {
		panic(err)
	}

	// Use DecryptBase64 if your input is base64.
	plain, err = des.TripleCBCDecrypter(key, iv, cryptox.UnPaddingPKCS7).DecryptBase64(cryptedBase64)
	if err != nil {
		panic(err)
	}

	fmt.Println("plain:", string(plain))
}
