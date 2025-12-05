// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hash

import (
	"hash/crc32"
	"hash/crc64"
)

var (
	tableIEEE = crc32.IEEETable
	tableISO  = crc64.MakeTable(crc64.ISO)
	tableECMA = crc64.MakeTable(crc64.ECMA)
)

// CRC32 uses given table to checksum data.
// Use IEEE table if passed table is nil.
func CRC32(data []byte, table *crc32.Table) uint32 {
	if table == nil {
		table = tableIEEE
	}

	return crc32.Checksum(data, table)
}

// CRC32IEEE uses ieee table to checksum data.
func CRC32IEEE(data []byte) uint32 {
	return CRC32(data, tableIEEE)
}

// CRC64 uses given table to checksum data.
// Use ISO table if passed table is nil.
func CRC64(data []byte, table *crc64.Table) uint64 {
	if table == nil {
		table = tableISO
	}

	return crc64.Checksum(data, table)
}

// CRC64ISO uses iso table to checksum data.
func CRC64ISO(data []byte) uint64 {
	return CRC64(data, tableISO)
}

// CRC64ECMA uses ecma table to checksum data.
func CRC64ECMA(data []byte) uint64 {
	return CRC64(data, tableECMA)
}
