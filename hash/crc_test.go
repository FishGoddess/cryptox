// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hash

import (
	"hash/crc32"
	"hash/crc64"
	"testing"
)

// go test -v -cover -run=^TestCRC32$
func TestCRC32(t *testing.T) {
	cases := map[string]string{
		"":      "00000000",
		"123":   "884863d2",
		"你好，世界": "acf5da54",
	}

	for input, expect := range cases {
		crc, crcNumber := CRC32([]byte(input), TableIEEE)
		if crc.Hex() != expect {
			t.Errorf("input %s: crc %s != expect %s", input, crc.Hex(), expect)
		}

		expectNumber := crc32.ChecksumIEEE([]byte(input))
		if crcNumber != expectNumber {
			t.Errorf("input %s: crcNumber %d != expectNumber %d", input, crcNumber, expectNumber)
		}
	}
}

// go test -v -cover -run=^TestCRC32IEEE$
func TestCRC32IEEE(t *testing.T) {
	cases := map[string]string{
		"":      "00000000",
		"123":   "884863d2",
		"你好，世界": "acf5da54",
	}

	for input, expect := range cases {
		crc, crcNumber := CRC32IEEE([]byte(input))
		if crc.Hex() != expect {
			t.Errorf("input %s: crc %s != expect %s", input, crc.Hex(), expect)
		}

		expectNumber := crc32.ChecksumIEEE([]byte(input))
		if crcNumber != expectNumber {
			t.Errorf("input %s: crcNumber %d != expectNumber %d", input, crcNumber, expectNumber)
		}
	}
}

// go test -v -cover -run=^TestCRC64$
func TestCRC64(t *testing.T) {
	cases := map[string]string{
		"":      "0000000000000000",
		"123":   "4001b32000000000",
		"你好，世界": "97788e871c4b3b66",
	}

	for input, expect := range cases {
		crc, crcNumber := CRC64([]byte(input), TableISO)
		if crc.Hex() != expect {
			t.Errorf("input %s: crc %s != expect %s", input, crc.Hex(), expect)
		}

		expectNumber := crc64.Checksum([]byte(input), crc64.MakeTable(crc64.ISO))
		if crcNumber != expectNumber {
			t.Errorf("input %s: crcNumber %d != expectNumber %d", input, crcNumber, expectNumber)
		}
	}
}

// go test -v -cover -run=^TestCRC64ISO$
func TestCRC64ISO(t *testing.T) {
	cases := map[string]string{
		"":      "0000000000000000",
		"123":   "4001b32000000000",
		"你好，世界": "97788e871c4b3b66",
	}

	for input, expect := range cases {
		crc, crcNumber := CRC64ISO([]byte(input))
		if crc.Hex() != expect {
			t.Errorf("input %s: crc %s != expect %s", input, crc.Hex(), expect)
		}

		expectNumber := crc64.Checksum([]byte(input), crc64.MakeTable(crc64.ISO))
		if crcNumber != expectNumber {
			t.Errorf("input %s: crcNumber %d != expectNumber %d", input, crcNumber, expectNumber)
		}
	}
}

// go test -v -cover -run=^TestCRC64ECMA$
func TestCRC64ECMA(t *testing.T) {
	cases := map[string]string{
		"":      "0000000000000000",
		"123":   "30232844071cc561",
		"你好，世界": "3eba78bfcc65bffb",
	}

	for input, expect := range cases {
		crc, crcNumber := CRC64ECMA([]byte(input))
		if crc.Hex() != expect {
			t.Errorf("input %s: crc %s != expect %s", input, crc.Hex(), expect)
		}

		expectNumber := crc64.Checksum([]byte(input), crc64.MakeTable(crc64.ECMA))
		if crcNumber != expectNumber {
			t.Errorf("input %s: crcNumber %d != expectNumber %d", input, crcNumber, expectNumber)
		}
	}
}
