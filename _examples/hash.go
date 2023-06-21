// Copyright 2023 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/FishGoddess/cryptox"
	"github.com/FishGoddess/cryptox/hash"
)

func main() {
	data := cryptox.FromString("你好，世界")
	fmt.Println("data:", data)

	// All hashing functions will return a cryptox.Bytes type which can be encoded to hex and base64.

	md5, _ := hash.MD5(data)
	fmt.Println("md5 hex:", md5.Hex())
	fmt.Println("md5 base64:", md5.Base64())

	sha1, _ := hash.SHA1(data)
	fmt.Println("sha1 hex:", sha1.Hex())
	fmt.Println("sha1 base64:", sha1.Base64())

	sha224, _ := hash.SHA224(data)
	fmt.Println("sha224 hex:", sha224.Hex())
	fmt.Println("sha224 base64:", sha224.Base64())

	sha256, _ := hash.SHA256(data)
	fmt.Println("sha256 hex:", sha256.Hex())
	fmt.Println("sha256 base64:", sha256.Base64())

	sha384, _ := hash.SHA384(data)
	fmt.Println("sha384 hex:", sha384.Hex())
	fmt.Println("sha384 base64:", sha384.Base64())

	sha512, _ := hash.SHA512(data)
	fmt.Println("sha512 hex:", sha512.Hex())
	fmt.Println("sha512 base64:", sha512.Base64())

	// HMAC uses a hash and key to work, and we choose sha256 here.
	key := cryptox.FromString("12345678")
	hmac, _ := hash.HMAC(key).SHA256(data)
	fmt.Printf("hmac with key %s hex: %s\n", key, hmac.Hex())
	fmt.Printf("hmac with key %s base64: %s\n", key, hmac.Base64())

	crc, crc32, _ := hash.CRC32IEEE(data)
	fmt.Printf("crc32 with ieee: %d\n", crc32)
	fmt.Printf("crc32 with ieee hex: %s\n", crc.Hex())
	fmt.Printf("crc32 with ieee base64: %s\n", crc.Base64())

	crc, crc64, _ := hash.CRC64ISO(data)
	fmt.Printf("crc64 with iso: %d\n", crc64)
	fmt.Printf("crc64 with iso hex: %s\n", crc.Hex())
	fmt.Printf("crc64 with iso base64: %s\n", crc.Base64())

	crc, crc64, _ = hash.CRC64ECMA(data)
	fmt.Printf("crc64 with ecma: %d\n", crc64)
	fmt.Printf("crc64 with ecma hex: %s\n", crc.Hex())
	fmt.Printf("crc64 with ecma base64: %s\n", crc.Base64())

	fnv, fnv32, _ := hash.Fnv32(data)
	fmt.Printf("fnv-1/32: %d\n", fnv32)
	fmt.Printf("fnv-1/32 hex: %s\n", fnv.Hex())
	fmt.Printf("fnv-1/32 base64: %s\n", fnv.Base64())

	fnv, fnv32, _ = hash.Fnv32a(data)
	fmt.Printf("fnv-1/32a: %d\n", fnv32)
	fmt.Printf("fnv-1/32a hex: %s\n", fnv.Hex())
	fmt.Printf("fnv-1/32a base64: %s\n", fnv.Base64())

	fnv, fnv64, _ := hash.Fnv64(data)
	fmt.Printf("fnv-1/64: %d\n", fnv64)
	fmt.Printf("fnv-1/64 hex: %s\n", fnv.Hex())
	fmt.Printf("fnv-1/64 base64: %s\n", fnv.Base64())

	fnv, fnv64, _ = hash.Fnv64a(data)
	fmt.Printf("fnv-1/64a: %d\n", fnv64)
	fmt.Printf("fnv-1/64a hex: %s\n", fnv.Hex())
	fmt.Printf("fnv-1/64a base64: %s\n", fnv.Base64())

	fnv, _ = hash.Fnv128(data)
	fmt.Printf("fnv-1/128 hex: %s\n", fnv.Hex())
	fmt.Printf("fnv-1/128 base64: %s\n", fnv.Base64())

	fnv, _ = hash.Fnv128a(data)
	fmt.Printf("fnv-1/128a hex: %s\n", fnv.Hex())
	fmt.Printf("fnv-1/128a base64: %s\n", fnv.Base64())
}
