// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hash

import (
	"hash/crc32"
	"hash/crc64"
	"testing"
)

// go test -v -cover -count=1 -test.cpu=1 -run=^TestCRC32$
func TestCRC32(t *testing.T) {
	cases := map[string]uint32{
		"":      0,
		"123":   2286445522,
		"你好，世界": 2901793364,
	}

	for input, expect := range cases {
		crc := CRC32([]byte(input), tableIEEE)
		if crc != expect {
			t.Fatalf("input %s: crc %d != expect %d", input, crc, expect)
		}

		expectNumber := crc32.ChecksumIEEE([]byte(input))
		if crc != expectNumber {
			t.Fatalf("input %s: crc %d != expectNumber %d", input, crc, expectNumber)
		}
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestCRC32IEEE$
func TestCRC32IEEE(t *testing.T) {
	cases := map[string]uint32{
		"":      0,
		"123":   2286445522,
		"你好，世界": 2901793364,
	}

	for input, expect := range cases {
		crc := CRC32IEEE([]byte(input))
		if crc != expect {
			t.Fatalf("input %s: crc %d != expect %d", input, crc, expect)
		}

		expectNumber := crc32.ChecksumIEEE([]byte(input))
		if crc != expectNumber {
			t.Fatalf("input %s: crc %d != expectNumber %d", input, crc, expectNumber)
		}
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestCRC64$
func TestCRC64(t *testing.T) {
	cases := map[string]uint64{
		"":      0,
		"123":   4612164443424423936,
		"你好，世界": 10914630407878818662,
	}

	for input, expect := range cases {
		crc := CRC64([]byte(input), tableISO)
		if crc != expect {
			t.Fatalf("input %s: crc %d != expect %d", input, crc, expect)
		}

		expectNumber := crc64.Checksum([]byte(input), crc64.MakeTable(crc64.ISO))
		if crc != expectNumber {
			t.Fatalf("input %s: crc %d != expectNumber %d", input, crc, expectNumber)
		}
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestCRC64ISO$
func TestCRC64ISO(t *testing.T) {
	cases := map[string]uint64{
		"":      0,
		"123":   4612164443424423936,
		"你好，世界": 10914630407878818662,
	}

	for input, expect := range cases {
		crc := CRC64ISO([]byte(input))
		if crc != expect {
			t.Fatalf("input %s: crc %d != expect %d", input, crc, expect)
		}

		expectNumber := crc64.Checksum([]byte(input), crc64.MakeTable(crc64.ISO))
		if crc != expectNumber {
			t.Fatalf("input %s: crc %d != expectNumber %d", input, crc, expectNumber)
		}
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestCRC64ECMA$
func TestCRC64ECMA(t *testing.T) {
	cases := map[string]uint64{
		"":      0,
		"123":   3468660410647627105,
		"你好，世界": 4520057941183021051,
	}

	for input, expect := range cases {
		crc := CRC64ECMA([]byte(input))
		if crc != expect {
			t.Fatalf("input %s: crc %d != expect %d", input, crc, expect)
		}

		expectNumber := crc64.Checksum([]byte(input), crc64.MakeTable(crc64.ECMA))
		if crc != expectNumber {
			t.Fatalf("input %s: crc %d != expectNumber %d", input, crc, expectNumber)
		}
	}
}
