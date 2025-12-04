// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hash

import (
	"hash/fnv"
)

// Fnv32 uses fnv-1/32bit to hash bs.
func Fnv32(bs []byte) uint32 {
	hash32 := fnv.New32()
	hash32.Write(bs)
	return hash32.Sum32()
}

// Fnv32a uses fnv-1a/32bit to hash bs.
func Fnv32a(bs []byte) uint32 {
	hash32 := fnv.New32a()
	hash32.Write(bs)
	return hash32.Sum32()
}

// Fnv64 uses fnv-1/64bit to hash bs.
func Fnv64(bs []byte) uint64 {
	hash64 := fnv.New64()
	hash64.Write(bs)
	return hash64.Sum64()
}

// Fnv64a uses fnv-1a/64bit to hash bs.
func Fnv64a(bs []byte) uint64 {
	hash64 := fnv.New64a()
	hash64.Write(bs)
	return hash64.Sum64()
}

// Fnv128 uses fnv-1/128bit to hash bs.
func Fnv128(bs []byte, opts ...Option) []byte {
	conf := newConfig().Apply(opts...)

	hash128 := fnv.New128()
	hash128.Write(bs)

	sum := hash128.Sum(nil)
	return conf.encoding.Encode(sum)
}

// Fnv128a uses fnv-1a/128bit to hash bs.
func Fnv128a(bs []byte, opts ...Option) []byte {
	conf := newConfig().Apply(opts...)

	hash128 := fnv.New128a()
	hash128.Write(bs)

	sum := hash128.Sum(nil)
	return conf.encoding.Encode(sum)
}
