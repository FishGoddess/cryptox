// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/FishGoddess/cryptox/hmac"
)

func main() {
	data := []byte("你好，世界")
	fmt.Printf("data: %s\n", data)

	key := []byte("key")
	fmt.Printf("key: %s\n", key)

	md5 := hmac.MD5(data, key)
	md5Hex := hmac.MD5(data, key, hmac.WithHex())
	md5Base64 := hmac.MD5(data, key, hmac.WithBase64())
	fmt.Printf("md5: %s\n", md5)
	fmt.Printf("md5 hex: %s\n", md5Hex)
	fmt.Printf("md5 base64: %s\n", md5Base64)

	sha1 := hmac.SHA1(data, key)
	sha1Hex := hmac.SHA1(data, key, hmac.WithHex())
	sha1Base64 := hmac.SHA1(data, key, hmac.WithBase64())
	fmt.Printf("sha1: %s\n", sha1)
	fmt.Printf("sha1 hex: %s\n", sha1Hex)
	fmt.Printf("sha1 base64: %s\n", sha1Base64)

	sha224 := hmac.SHA224(data, key)
	sha224Hex := hmac.SHA224(data, key, hmac.WithHex())
	sha224Base64 := hmac.SHA224(data, key, hmac.WithBase64())
	fmt.Printf("sha224: %s\n", sha224)
	fmt.Printf("sha224 hex: %s\n", sha224Hex)
	fmt.Printf("sha224 base64: %s\n", sha224Base64)

	sha256 := hmac.SHA256(data, key)
	sha256Hex := hmac.SHA256(data, key, hmac.WithHex())
	sha256Base64 := hmac.SHA256(data, key, hmac.WithBase64())
	fmt.Printf("sha256: %s\n", sha256)
	fmt.Printf("sha256 hex: %s\n", sha256Hex)
	fmt.Printf("sha256 base64: %s\n", sha256Base64)

	sha384 := hmac.SHA384(data, key)
	sha384Hex := hmac.SHA384(data, key, hmac.WithHex())
	sha384Base64 := hmac.SHA384(data, key, hmac.WithBase64())
	fmt.Printf("sha384: %s\n", sha384)
	fmt.Printf("sha384 hex: %s\n", sha384Hex)
	fmt.Printf("sha384 base64: %s\n", sha384Base64)

	sha512 := hmac.SHA512(data, key)
	sha512Hex := hmac.SHA512(data, key, hmac.WithHex())
	sha512Base64 := hmac.SHA512(data, key, hmac.WithBase64())
	fmt.Printf("sha512: %s\n", sha512)
	fmt.Printf("sha512 hex: %s\n", sha512Hex)
	fmt.Printf("sha512 base64: %s\n", sha512Base64)
}
