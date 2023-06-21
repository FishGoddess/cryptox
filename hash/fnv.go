// Copyright 2023 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hash

import (
	"hash/fnv"

	"github.com/FishGoddess/cryptox"
)

// Fnv32 uses fnv-1/32bit to hash bs.
func Fnv32(bs cryptox.Bytes) (cryptox.Bytes, uint32, error) {
	hash32 := fnv.New32()
	if _, err := hash32.Write(bs); err != nil {
		return nil, 0, err
	}

	return hash32.Sum(nil), hash32.Sum32(), nil
}

// Fnv32a uses fnv-1a/32bit to hash bs.
func Fnv32a(bs cryptox.Bytes) (cryptox.Bytes, uint32, error) {
	hash32 := fnv.New32a()
	if _, err := hash32.Write(bs); err != nil {
		return nil, 0, err
	}

	return hash32.Sum(nil), hash32.Sum32(), nil
}

// Fnv64 uses fnv-1/64bit to hash bs.
func Fnv64(bs cryptox.Bytes) (cryptox.Bytes, uint64, error) {
	hash64 := fnv.New64()
	if _, err := hash64.Write(bs); err != nil {
		return nil, 0, err
	}

	return hash64.Sum(nil), hash64.Sum64(), nil
}

// Fnv64a uses fnv-1a/64bit to hash bs.
func Fnv64a(bs cryptox.Bytes) (cryptox.Bytes, uint64, error) {
	hash64 := fnv.New64a()
	if _, err := hash64.Write(bs); err != nil {
		return nil, 0, err
	}

	return hash64.Sum(nil), hash64.Sum64(), nil
}

// Fnv128 uses fnv-1/128bit to hash bs.
func Fnv128(bs cryptox.Bytes) (cryptox.Bytes, error) {
	hash128 := fnv.New128()
	if _, err := hash128.Write(bs); err != nil {
		return nil, err
	}

	return hash128.Sum(nil), nil
}

// Fnv128a uses fnv-1a/128bit to hash bs.
func Fnv128a(bs cryptox.Bytes) (cryptox.Bytes, error) {
	hash128 := fnv.New128a()
	if _, err := hash128.Write(bs); err != nil {
		return nil, err
	}

	return hash128.Sum(nil), nil
}
