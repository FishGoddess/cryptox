// Copyright 2023 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hash

import (
	"bytes"
	"hash/fnv"
	"testing"
)

// go test -v -cover -run=^TestFnv32$
func TestFnv32(t *testing.T) {
	cases := map[string]string{
		"":      "811c9dc5",
		"123":   "72d607bb",
		"你好，世界": "f0de4cd0",
	}

	for input, expect := range cases {
		fnv32, fnv32Number, err := Fnv32([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if fnv32.Hex() != expect {
			t.Errorf("input %s: fnv32 %s != expect %s", input, fnv32.Hex(), expect)
		}

		hash32 := fnv.New32()
		hash32.Write([]byte(input))

		expectNumber := hash32.Sum32()
		if fnv32Number != expectNumber {
			t.Errorf("input %s: fnv32Number %d != expectNumber %d", input, fnv32Number, expectNumber)
		}
	}
}

// go test -v -cover -run=^TestFnv32a$
func TestFnv32a(t *testing.T) {
	cases := map[string]string{
		"":      "811c9dc5",
		"123":   "7238631b",
		"你好，世界": "e57e15b6",
	}

	for input, expect := range cases {
		fnv32, fnv32Number, err := Fnv32a([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if fnv32.Hex() != expect {
			t.Errorf("input %s: fnv32 %s != expect %s", input, fnv32.Hex(), expect)
		}

		hash32 := fnv.New32a()
		hash32.Write([]byte(input))

		expectNumber := hash32.Sum32()
		if fnv32Number != expectNumber {
			t.Errorf("input %s: fnv32Number %d != expectNumber %d", input, fnv32Number, expectNumber)
		}
	}
}

// go test -v -cover -run=^TestFnv64$
func TestFnv64(t *testing.T) {
	cases := map[string]string{
		"":      "cbf29ce484222325",
		"123":   "d97ffa186c3a60bb",
		"你好，世界": "3118c9955d46a2d0",
	}

	for input, expect := range cases {
		fnv64, fnv64Number, err := Fnv64([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if fnv64.Hex() != expect {
			t.Errorf("input %s: fnv64 %s != expect %s", input, fnv64.Hex(), expect)
		}

		hash64 := fnv.New64()
		hash64.Write([]byte(input))

		expectNumber := hash64.Sum64()
		if fnv64Number != expectNumber {
			t.Errorf("input %s: fnv64Number %d != expectNumber %d", input, fnv64Number, expectNumber)
		}
	}
}

// go test -v -cover -run=^TestFnv64a$
func TestFnv64a(t *testing.T) {
	cases := map[string]string{
		"":      "cbf29ce484222325",
		"123":   "456fc2181822c4db",
		"你好，世界": "fe310926beabb516",
	}

	for input, expect := range cases {
		fnv64, fnv64Number, err := Fnv64a([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if fnv64.Hex() != expect {
			t.Errorf("input %s: fnv64 %s != expect %s", input, fnv64.Hex(), expect)
		}

		hash64 := fnv.New64a()
		hash64.Write([]byte(input))

		expectNumber := hash64.Sum64()
		if fnv64Number != expectNumber {
			t.Errorf("input %s: fnv64Number %d != expectNumber %d", input, fnv64Number, expectNumber)
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
		fnv128, err := Fnv128([]byte(input))
		if err != nil {
			t.Error(err)
		}

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
		fnv128, err := Fnv128a([]byte(input))
		if err != nil {
			t.Error(err)
		}

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
