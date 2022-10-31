// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hash

import (
	"hash/fnv"

	"github.com/FishGoddess/cryptox"
)

// Fnv32 uses fnv-1/32bit to hash data.
func Fnv32(data cryptox.Bytes) (cryptox.Bytes, uint32) {
	hash32 := fnv.New32()
	hash32.Write(data)

	return hash32.Sum(nil), hash32.Sum32()
}

// Fnv32a uses fnv-1a/32bit to hash data.
func Fnv32a(data cryptox.Bytes) (cryptox.Bytes, uint32) {
	hash32 := fnv.New32a()
	hash32.Write(data)

	return hash32.Sum(nil), hash32.Sum32()
}

// Fnv64 uses fnv-1/64bit to hash data.
func Fnv64(data cryptox.Bytes) (cryptox.Bytes, uint64) {
	hash64 := fnv.New64()
	hash64.Write(data)

	return hash64.Sum(nil), hash64.Sum64()
}

// Fnv64a uses fnv-1a/64bit to hash data.
func Fnv64a(data cryptox.Bytes) (cryptox.Bytes, uint64) {
	hash64 := fnv.New64a()
	hash64.Write(data)

	return hash64.Sum(nil), hash64.Sum64()
}

// Fnv128 uses fnv-1/128bit to hash data.
func Fnv128(data cryptox.Bytes) cryptox.Bytes {
	hash64 := fnv.New128()
	hash64.Write(data)

	return hash64.Sum(nil)
}

// Fnv128a uses fnv-1a/128bit to hash data.
func Fnv128a(data cryptox.Bytes) cryptox.Bytes {
	hash64 := fnv.New128a()
	hash64.Write(data)

	return hash64.Sum(nil)
}
