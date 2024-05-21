// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/FishGoddess/cryptox/hmac"
)

func main() {
	key := []byte("12345678")
	fmt.Println("key:", key)

	data := []byte("你好，世界")
	fmt.Println("data:", data)

	md5, _ := hmac.MD5(key, data)
	fmt.Println("hmac md5 hex:", md5.Hex())
	fmt.Println("hmac md5 base64:", md5.Base64())

	sha1, _ := hmac.SHA1(key, data)
	fmt.Println("hmac sha1 hex:", sha1.Hex())
	fmt.Println("hmac sha1 base64:", sha1.Base64())

	sha224, _ := hmac.SHA224(key, data)
	fmt.Println("hmac sha224 hex:", sha224.Hex())
	fmt.Println("hmac sha224 base64:", sha224.Base64())

	sha256, _ := hmac.SHA256(key, data)
	fmt.Println("hmac sha256 hex:", sha256.Hex())
	fmt.Println("hmac sha256 base64:", sha256.Base64())

	sha384, _ := hmac.SHA384(key, data)
	fmt.Println("hmac sha384 hex:", sha384.Hex())
	fmt.Println("hmac sha384 base64:", sha384.Base64())

	sha512, _ := hmac.SHA512(key, data)
	fmt.Println("hmac sha512 hex:", sha512.Hex())
	fmt.Println("hmac sha512 base64:", sha512.Base64())
}
