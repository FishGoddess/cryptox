// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hash

import (
	"hash/fnv"
	"slices"
	"testing"

	"github.com/FishGoddess/cryptox/bytes/encoding"
)

// go test -v -cover -run=^TestFnv32$
func TestFnv32(t *testing.T) {
	testCases := map[string]uint32{
		"":      2166136261,
		"123":   1926629307,
		"你好，世界": 4041100496,
	}

	for data, expect := range testCases {
		got := Fnv32([]byte(data))
		if got != expect {
			t.Fatalf("data %q: got %d != expect %d", data, got, expect)
		}

		hash32 := fnv.New32()
		hash32.Write([]byte(data))

		expect = hash32.Sum32()
		if got != expect {
			t.Fatalf("data %q: got %d != expect %d", data, got, expect)
		}
	}
}

// go test -v -cover -run=^TestFnv32a$
func TestFnv32a(t *testing.T) {
	testCases := map[string]uint32{
		"":      2166136261,
		"123":   1916298011,
		"你好，世界": 3850245558,
	}

	for data, expect := range testCases {
		got := Fnv32a([]byte(data))
		if got != expect {
			t.Fatalf("data %q: got %d != expect %d", data, got, expect)
		}

		hash32 := fnv.New32a()
		hash32.Write([]byte(data))

		expect = hash32.Sum32()
		if got != expect {
			t.Fatalf("data %q: got %d != expect %d", data, got, expect)
		}
	}
}

// go test -v -cover -run=^TestFnv64$
func TestFnv64(t *testing.T) {
	testCases := map[string]uint64{
		"":      14695981039346656037,
		"123":   15672520211074539707,
		"你好，世界": 3537799150651744976,
	}

	for data, expect := range testCases {
		got := Fnv64([]byte(data))
		if got != expect {
			t.Fatalf("data %q: got %d != expect %d", data, got, expect)
		}

		hash64 := fnv.New64()
		hash64.Write([]byte(data))

		expect = hash64.Sum64()
		if got != expect {
			t.Fatalf("data %q: got %d != expect %d", data, got, expect)
		}
	}
}

// go test -v -cover -run=^TestFnv64a$
func TestFnv64a(t *testing.T) {
	testCases := map[string]uint64{
		"":      14695981039346656037,
		"123":   5003431119771845851,
		"你好，世界": 18316431221504849174,
	}

	for data, expect := range testCases {
		got := Fnv64a([]byte(data))
		if got != expect {
			t.Fatalf("data %q: got %d != expect %d", data, got, expect)
		}

		hash64 := fnv.New64a()
		hash64.Write([]byte(data))

		expect = hash64.Sum64()
		if got != expect {
			t.Fatalf("data %q: got %d != expect %d", data, got, expect)
		}
	}
}

// go test -v -cover -run=^TestFnv128$
func TestFnv128(t *testing.T) {
	testCases := map[string][]byte{
		"":      []byte("6c62272e07bb014262b821756295c58d"),
		"123":   []byte("a68bb31a848b5822836dbc78c6f7cf2b"),
		"你好，世界": []byte("a143d39fc0ccf3153099c75a3ae16e50"),
	}

	for data, expect := range testCases {
		got := Fnv128([]byte(data), encoding.Hex)
		if !slices.Equal(got, expect) {
			t.Fatalf("data %q: got %s != expect %s", data, got, expect)
		}

		hash128 := fnv.New128()
		hash128.Write([]byte(data))

		expect = hash128.Sum(nil)
		expect = encoding.Hex.Encode(expect)
		if !slices.Equal(got, expect) {
			t.Fatalf("data %q: got %s != expectBytes %s", data, got, expect)
		}
	}
}

// go test -v -cover -run=^TestFnv128a$
func TestFnv128a(t *testing.T) {
	testCases := map[string][]byte{
		"":      []byte("6c62272e07bb014262b821756295c58d"),
		"123":   []byte("a68c893b0c8b5822836dbc791eed46cb"),
		"你好，世界": []byte("c8a3e17923084bf6e151c7caa750d68e"),
	}

	for data, expect := range testCases {
		got := Fnv128a([]byte(data), encoding.Hex)
		if !slices.Equal(got, expect) {
			t.Fatalf("data %q: got %s != expect %s", data, got, expect)
		}

		hash128 := fnv.New128a()
		hash128.Write([]byte(data))

		expect = hash128.Sum(nil)
		expect = encoding.Hex.Encode(expect)
		if !slices.Equal(got, expect) {
			t.Fatalf("data %q: got %s != expect %s", data, got, expect)
		}
	}
}
