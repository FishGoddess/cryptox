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

	hmac, _ := hmac.MD5(key, data)
	fmt.Printf("hmac md5 hex: %s\n", hmac.Hex())
	fmt.Printf("hmac md5 base64: %s\n", hmac.Base64())

	hmac, _ = hmac.SHA1(key, data)
	fmt.Printf("hmac sha1 hex: %s\n", hmac.Hex())
	fmt.Printf("hmac sha1 base64: %s\n", hmac.Base64())

	hmac, _ = hmac.SHA224(key, data)
	fmt.Printf("hmac sha224 hex: %s\n", hmac.Hex())
	fmt.Printf("hmac sha224 base64: %s\n", hmac.Base64())

	hmac, _ = hmac.SHA256(key, data)
	fmt.Printf("hmac sha256 hex: %s\n", hmac.Hex())
	fmt.Printf("hmac sha256 base64: %s\n", hmac.Base64())

	hmac, _ = hmac.SHA384(key, data)
	fmt.Printf("hmac sha384 hex: %s\n", hmac.Hex())
	fmt.Printf("hmac sha384 base64: %s\n", hmac.Base64())

	hmac, _ = hmac.SHA512(key, data)
	fmt.Printf("hmac sha512 hex: %s\n", hmac.Hex())
	fmt.Printf("hmac sha512 base64: %s\n", hmac.Base64())
}
