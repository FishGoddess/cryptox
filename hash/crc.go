// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hash

import (
	"hash/crc32"
	"hash/crc64"

	"github.com/FishGoddess/cryptox"
)

var (
	// TableIEEE is ieee table for crc32.
	TableIEEE = crc32.IEEETable

	// TableISO is iso table for crc64.
	TableISO = crc64.MakeTable(crc64.ISO)

	// TableECMA is ecma table for crc64.
	TableECMA = crc64.MakeTable(crc64.ECMA)
)

// Table32 is an alias of crc32.Table.
type Table32 = crc32.Table

// Table64 is an alias of crc64.Table.
type Table64 = crc64.Table

// CRC32 uses given table to checksum data.
// Use IEEE table if passed table is nil.
func CRC32(data cryptox.Bytes, table *Table32) (cryptox.Bytes, uint32) {
	if table == nil {
		table = TableIEEE
	}

	hash32 := crc32.New(table)
	hash32.Write(data)

	return hash32.Sum(nil), hash32.Sum32()
}

// CRC32IEEE uses ieee table to checksum data.
func CRC32IEEE(data cryptox.Bytes) (cryptox.Bytes, uint32) {
	return CRC32(data, TableIEEE)
}

// CRC64 uses given table to checksum data.
// Use ISO table if passed table is nil.
func CRC64(data cryptox.Bytes, table *Table64) (cryptox.Bytes, uint64) {
	if table == nil {
		table = TableISO
	}

	hash64 := crc64.New(table)
	hash64.Write(data)

	return hash64.Sum(nil), hash64.Sum64()
}

// CRC64ISO uses iso table to checksum data.
func CRC64ISO(data cryptox.Bytes) (cryptox.Bytes, uint64) {
	return CRC64(data, TableISO)
}

// CRC64ECMA uses ecma table to checksum data.
func CRC64ECMA(data cryptox.Bytes) (cryptox.Bytes, uint64) {
	return CRC64(data, TableECMA)
}
