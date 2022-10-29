// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/FishGoddess/cryptox"
	"github.com/FishGoddess/cryptox/hash"
)

func main() {
	data := []byte("你好，世界")
	fmt.Println("data:", string(data))

	// All hashing functions will return a cryptox.Bytes type which can be encoded to hex and base64.

	md5 := hash.MD5(data)
	fmt.Println("md5 hex:", md5.Hex())
	fmt.Println("md5 base64:", md5.Base64())

	sha1 := hash.SHA1(data)
	fmt.Println("sha1 hex:", sha1.Hex())
	fmt.Println("sha1 base64:", sha1.Base64())

	sha224 := hash.SHA224(data)
	fmt.Println("sha224 hex:", sha224.Hex())
	fmt.Println("sha224 base64:", sha224.Base64())

	sha256 := hash.SHA256(data)
	fmt.Println("sha256 hex:", sha256.Hex())
	fmt.Println("sha256 base64:", sha256.Base64())

	sha384 := hash.SHA384(data)
	fmt.Println("sha384 hex:", sha384.Hex())
	fmt.Println("sha384 base64:", sha384.Base64())

	sha512 := hash.SHA512(data)
	fmt.Println("sha512 hex:", sha512.Hex())
	fmt.Println("sha512 base64:", sha512.Base64())

	// HMAC uses a hash and key to work, and we choose sha256 here.
	key := "12345678"
	hmac := hash.HMAC(cryptox.SHA256, []byte(key), data)
	fmt.Printf("hmac with key %s hex: %s\n", key, hmac.Hex())
	fmt.Printf("hmac with key %s base64: %s\n", key, hmac.Base64())
}
