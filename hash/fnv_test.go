// Copyright 2023 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hash

import (
	"bytes"
	"hash/fnv"
	"testing"

	"github.com/FishGoddess/cryptox"
)

// go test -v -cover -run=^TestFnv32$
func TestFnv32(t *testing.T) {
	cases := map[string]uint32{
		"":      2166136261,
		"123":   1926629307,
		"你好，世界": 4041100496,
	}

	for input, expect := range cases {
		fnv32 := Fnv32(cryptox.FromString(input))
		if fnv32 != expect {
			t.Errorf("input %s: fnv32 %d != expect %d", input, fnv32, expect)
		}

		hash32 := fnv.New32()
		hash32.Write([]byte(input))

		expectNumber := hash32.Sum32()
		if fnv32 != expectNumber {
			t.Errorf("input %s: fnv32 %d != expectNumber %d", input, fnv32, expectNumber)
		}
	}
}

// go test -v -cover -run=^TestFnv32a$
func TestFnv32a(t *testing.T) {
	cases := map[string]uint32{
		"":      2166136261,
		"123":   1916298011,
		"你好，世界": 3850245558,
	}

	for input, expect := range cases {
		fnv32a := Fnv32a(cryptox.FromString(input))
		if fnv32a != expect {
			t.Errorf("input %s: fnv32a %d != expect %d", input, fnv32a, expect)
		}

		hash32 := fnv.New32a()
		hash32.Write([]byte(input))

		expectNumber := hash32.Sum32()
		if fnv32a != expectNumber {
			t.Errorf("input %s: fnv32a %d != expectNumber %d", input, fnv32a, expectNumber)
		}
	}
}

// go test -v -cover -run=^TestFnv64$
func TestFnv64(t *testing.T) {
	cases := map[string]uint64{
		"":      14695981039346656037,
		"123":   15672520211074539707,
		"你好，世界": 3537799150651744976,
	}

	for input, expect := range cases {
		fnv64 := Fnv64(cryptox.FromString(input))
		if fnv64 != expect {
			t.Errorf("input %s: fnv64 %d != expect %d", input, fnv64, expect)
		}

		hash64 := fnv.New64()
		hash64.Write([]byte(input))

		expectNumber := hash64.Sum64()
		if fnv64 != expectNumber {
			t.Errorf("input %s: fnv64 %d != expectNumber %d", input, fnv64, expectNumber)
		}
	}
}

// go test -v -cover -run=^TestFnv64a$
func TestFnv64a(t *testing.T) {
	cases := map[string]uint64{
		"":      14695981039346656037,
		"123":   5003431119771845851,
		"你好，世界": 18316431221504849174,
	}

	for input, expect := range cases {
		fnv64a := Fnv64a(cryptox.FromString(input))
		if fnv64a != expect {
			t.Errorf("input %s: fnv64a %d != expect %d", input, fnv64a, expect)
		}

		hash64 := fnv.New64a()
		hash64.Write([]byte(input))

		expectNumber := hash64.Sum64()
		if fnv64a != expectNumber {
			t.Errorf("input %s: fnv64a %d != expectNumber %d", input, fnv64a, expectNumber)
		}
	}
}

// go test -v -cover -run=^TestFnv128$
func TestFnv128(t *testing.T) {
	cases := map[string]string{
		"":      "6c62272e07bb014262b821756295c58d",
		"123":   "a68bb31a848b5822836dbc78c6f7cf2b",
		"你好，世界": "a143d39fc0ccf3153099c75a3ae16e50",
	}

	for input, expect := range cases {
		fnv128 := Fnv128([]byte(input))
		if fnv128.Hex() != expect {
			t.Errorf("input %s: fnv128 %s != expect %s", input, fnv128.Hex(), expect)
		}

		hash128 := fnv.New128()
		hash128.Write([]byte(input))

		expectBytes := hash128.Sum(nil)
		if !bytes.Equal(fnv128, expectBytes) {
			t.Errorf("input %s: fnv128 %+v != expectBytes %+v", input, fnv128, expectBytes)
		}
	}
}

// go test -v -cover -run=^TestFnv128a$
func TestFnv128a(t *testing.T) {
	cases := map[string]string{
		"":      "6c62272e07bb014262b821756295c58d",
		"123":   "a68c893b0c8b5822836dbc791eed46cb",
		"你好，世界": "c8a3e17923084bf6e151c7caa750d68e",
	}

	for input, expect := range cases {
		fnv128 := Fnv128a([]byte(input))
		if fnv128.Hex() != expect {
			t.Errorf("input %s: fnv128 %s != expect %s", input, fnv128.Hex(), expect)
		}

		hash128 := fnv.New128a()
		hash128.Write([]byte(input))

		expectBytes := hash128.Sum(nil)
		if !bytes.Equal(fnv128, expectBytes) {
			t.Errorf("input %s: fnv128 %+v != expectBytes %+v", input, fnv128, expectBytes)
		}
	}
}
