// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/FishGoddess/cryptox/bytes/encoding"
	"github.com/FishGoddess/cryptox/hmac"
)

func main() {
	key := []byte("key")
	fmt.Printf("key: %s\n", key)

	data := []byte("你好，世界")
	fmt.Printf("data: %s\n", data)

	md5Hex := hmac.MD5(data, key, encoding.Hex)
	md5Base64 := hmac.MD5(data, key, encoding.Base64)
	fmt.Printf("md5 hex: %s\n", md5Hex)
	fmt.Printf("md5 base64: %s\n", md5Base64)

	sha1Hex := hmac.SHA1(data, key, encoding.Hex)
	sha1Base64 := hmac.SHA1(data, key, encoding.Base64)
	fmt.Printf("sha1 hex: %s\n", sha1Hex)
	fmt.Printf("sha1 base64: %s\n", sha1Base64)

	sha224Hex := hmac.SHA224(data, key, encoding.Hex)
	sha224Base64 := hmac.SHA224(data, key, encoding.Base64)
	fmt.Printf("sha224 hex: %s\n", sha224Hex)
	fmt.Printf("sha224 base64: %s\n", sha224Base64)

	sha256Hex := hmac.SHA256(data, key, encoding.Hex)
	sha256Base64 := hmac.SHA256(data, key, encoding.Base64)
	fmt.Printf("sha256 hex: %s\n", sha256Hex)
	fmt.Printf("sha256 base64: %s\n", sha256Base64)

	sha384Hex := hmac.SHA384(data, key, encoding.Hex)
	sha384Base64 := hmac.SHA384(data, key, encoding.Base64)
	fmt.Printf("sha384 hex: %s\n", sha384Hex)
	fmt.Printf("sha384 base64: %s\n", sha384Base64)

	sha512Hex := hmac.SHA512(data, key, encoding.Hex)
	sha512Base64 := hmac.SHA512(data, key, encoding.Base64)
	fmt.Printf("sha512 hex: %s\n", sha512Hex)
	fmt.Printf("sha512 base64: %s\n", sha512Base64)
}
