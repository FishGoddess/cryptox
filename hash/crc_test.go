// Copyright 2024 FishGoddess. All rights reserved.
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
	testCases := map[string]uint32{
		"":      0,
		"123":   2286445522,
		"你好，世界": 2901793364,
	}

	for data, expect := range testCases {
		got := CRC32([]byte(data), tableIEEE)
		if got != expect {
			t.Fatalf("data %s: got %d != expect %d", data, got, expect)
		}

		expect = crc32.ChecksumIEEE([]byte(data))
		if got != expect {
			t.Fatalf("data %s: got %d != expect %d", data, got, expect)
		}
	}
}

// go test -v -cover -run=^TestCRC32IEEE$
func TestCRC32IEEE(t *testing.T) {
	testCases := map[string]uint32{
		"":      0,
		"123":   2286445522,
		"你好，世界": 2901793364,
	}

	for data, expect := range testCases {
		got := CRC32IEEE([]byte(data))
		if got != expect {
			t.Fatalf("data %s: got %d != expect %d", data, got, expect)
		}

		expect = crc32.ChecksumIEEE([]byte(data))
		if got != expect {
			t.Fatalf("data %s: got %d != expect %d", data, got, expect)
		}
	}
}

// go test -v -cover -run=^TestCRC64$
func TestCRC64(t *testing.T) {
	testCases := map[string]uint64{
		"":      0,
		"123":   4612164443424423936,
		"你好，世界": 10914630407878818662,
	}

	for data, expect := range testCases {
		got := CRC64([]byte(data), tableISO)
		if got != expect {
			t.Fatalf("data %s: got %d != expect %d", data, got, expect)
		}

		expect = crc64.Checksum([]byte(data), crc64.MakeTable(crc64.ISO))
		if got != expect {
			t.Fatalf("data %s: got %d != expect %d", data, got, expect)
		}
	}
}

// go test -v -cover -run=^TestCRC64ISO$
func TestCRC64ISO(t *testing.T) {
	testCases := map[string]uint64{
		"":      0,
		"123":   4612164443424423936,
		"你好，世界": 10914630407878818662,
	}

	for data, expect := range testCases {
		got := CRC64ISO([]byte(data))
		if got != expect {
			t.Fatalf("data %s: got %d != expect %d", data, got, expect)
		}

		expect = crc64.Checksum([]byte(data), crc64.MakeTable(crc64.ISO))
		if got != expect {
			t.Fatalf("data %s: got %d != expect %d", data, got, expect)
		}
	}
}

// go test -v -cover -run=^TestCRC64ECMA$
func TestCRC64ECMA(t *testing.T) {
	testCases := map[string]uint64{
		"":      0,
		"123":   3468660410647627105,
		"你好，世界": 4520057941183021051,
	}

	for data, expect := range testCases {
		got := CRC64ECMA([]byte(data))
		if got != expect {
			t.Fatalf("data %s: got %d != expect %d", data, got, expect)
		}

		expect = crc64.Checksum([]byte(data), crc64.MakeTable(crc64.ECMA))
		if got != expect {
			t.Fatalf("data %s: got %d != expect %d", data, got, expect)
		}
	}
}
