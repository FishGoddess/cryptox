// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/FishGoddess/cryptox/hash"
)

func main() {
	data := []byte("你好，世界")
	fmt.Println("data:", data)

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

	crc32 := hash.CRC32IEEE(data)
	fmt.Printf("crc32 with ieee: %d\n", crc32)

	crc64 := hash.CRC64ISO(data)
	fmt.Printf("crc64 with iso: %d\n", crc64)

	crc64 = hash.CRC64ECMA(data)
	fmt.Printf("crc64 with ecma: %d\n", crc64)

	fnv32 := hash.Fnv32(data)
	fmt.Printf("fnv-1/32: %d\n", fnv32)

	fnv32a := hash.Fnv32a(data)
	fmt.Printf("fnv-1/32a: %d\n", fnv32a)

	fnv64 := hash.Fnv64(data)
	fmt.Printf("fnv-1/64: %d\n", fnv64)

	fnv64a := hash.Fnv64a(data)
	fmt.Printf("fnv-1/64a: %d\n", fnv64a)

	fnv128 := hash.Fnv128(data)
	fmt.Printf("fnv-1/128 hex: %s\n", fnv128.Hex())
	fmt.Printf("fnv-1/128 base64: %s\n", fnv128.Base64())

	fnv128a := hash.Fnv128a(data)
	fmt.Printf("fnv-1/128a hex: %s\n", fnv128a.Hex())
	fmt.Printf("fnv-1/128a base64: %s\n", fnv128a.Base64())
}
