// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hash

import (
	"hash/crc32"
	"hash/crc64"

	"github.com/FishGoddess/cryptox"
)

var (
	tableIEEE = crc32.IEEETable
	tableISO  = crc64.MakeTable(crc64.ISO)
	tableECMA = crc64.MakeTable(crc64.ECMA)
)

type Table32 = crc32.Table

type Table64 = crc64.Table

// CRC32 uses given table to checksum bs.
// Use IEEE table if passed table is nil.
func CRC32(bs cryptox.Bytes, table *Table32) uint32 {
	if table == nil {
		table = tableIEEE
	}

	return crc32.Checksum(bs, table)
}

// CRC32IEEE uses ieee table to checksum bs.
func CRC32IEEE(bs cryptox.Bytes) uint32 {
	return CRC32(bs, tableIEEE)
}

// CRC64 uses given table to checksum bs.
// Use ISO table if passed table is nil.
func CRC64(bs cryptox.Bytes, table *Table64) uint64 {
	if table == nil {
		table = tableISO
	}

	return crc64.Checksum(bs, table)
}

// CRC64ISO uses iso table to checksum bs.
func CRC64ISO(bs cryptox.Bytes) uint64 {
	return CRC64(bs, tableISO)
}

// CRC64ECMA uses ecma table to checksum bs.
func CRC64ECMA(bs cryptox.Bytes) uint64 {
	return CRC64(bs, tableECMA)
}
