// Copyright 2023 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hash

import (
	stdcrc32 "hash/crc32"
	stdcrc64 "hash/crc64"

	"github.com/FishGoddess/cryptox"
)

var (
	tableIEEE = stdcrc32.IEEETable
	tableISO  = stdcrc64.MakeTable(stdcrc64.ISO)
	tableECMA = stdcrc64.MakeTable(stdcrc64.ECMA)
)

// Table32 is an alias of crc32.Table.
type Table32 = stdcrc32.Table

// Table64 is an alias of crc64.Table.
type Table64 = stdcrc64.Table

// CRC32 uses given table to checksum bs.
// Use IEEE table if passed table is nil.
func CRC32(bs cryptox.Bytes, table *Table32) (cryptox.Bytes, uint32, error) {
	if table == nil {
		table = tableIEEE
	}

	hash32 := stdcrc32.New(table)
	if _, err := hash32.Write(bs); err != nil {
		return nil, 0, err
	}

	return hash32.Sum(nil), hash32.Sum32(), nil
}

// CRC32IEEE uses ieee table to checksum bs.
func CRC32IEEE(bs cryptox.Bytes) (cryptox.Bytes, uint32, error) {
	return CRC32(bs, tableIEEE)
}

// CRC64 uses given table to checksum bs.
// Use ISO table if passed table is nil.
func CRC64(bs cryptox.Bytes, table *Table64) (cryptox.Bytes, uint64, error) {
	if table == nil {
		table = tableISO
	}

	hash64 := stdcrc64.New(table)
	if _, err := hash64.Write(bs); err != nil {
		return nil, 0, err
	}

	return hash64.Sum(nil), hash64.Sum64(), nil
}

// CRC64ISO uses iso table to checksum bs.
func CRC64ISO(bs cryptox.Bytes) (cryptox.Bytes, uint64, error) {
	return CRC64(bs, tableISO)
}

// CRC64ECMA uses ecma table to checksum bs.
func CRC64ECMA(bs cryptox.Bytes) (cryptox.Bytes, uint64, error) {
	return CRC64(bs, tableECMA)
}
