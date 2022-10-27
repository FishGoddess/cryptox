// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import "testing"

// go test -v -cover -run=^TestNoPadding$
func TestNoPadding(t *testing.T) {
	padder := NoPadding()

	blockSize := 8
	cases := map[string]string{
		string([]byte{}):                       string([]byte{}),
		string([]byte{1, 2, 3, 4, 5}):          string([]byte{1, 2, 3, 4, 5}),
		string([]byte{1, 2, 3, 4, 5, 6, 7, 8}): string([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
	}

	for data, expect := range cases {
		padding := padder.Padding([]byte(data), blockSize)
		if string(padding) != expect {
			t.Errorf("data %+v: padding %+v != expect %s", []byte(data), padding, []byte(expect))
		}
	}

	for data, expect := range cases {
		unPadding, err := padder.UnPadding([]byte(expect), blockSize)
		if err != nil {
			t.Error(err)
		}

		if string(unPadding) != data {
			t.Errorf("expect %+v: unPadding %+v != data %+v", []byte(expect), unPadding, []byte(data))
		}
	}
}

// go test -v -cover -run=^TestZeroPadding$
func TestZeroPadding(t *testing.T) {
	padder := ZeroPadding()

	blockSize := 8
	cases := map[string]string{
		string([]byte{}):                       string([]byte{0, 0, 0, 0, 0, 0, 0, 0}),
		string([]byte{1, 2, 3, 4, 5}):          string([]byte{1, 2, 3, 4, 5, 0, 0, 0}),
		string([]byte{1, 2, 3, 4, 5, 6, 7, 8}): string([]byte{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0}),
	}

	for data, expect := range cases {
		padding := padder.Padding([]byte(data), blockSize)
		if string(padding) != expect {
			t.Errorf("data %+v: padding %+v != expect %s", []byte(data), padding, []byte(expect))
		}
	}

	for data, expect := range cases {
		unPadding, err := padder.UnPadding([]byte(expect), blockSize)
		if err != nil {
			t.Error(err)
		}

		if string(unPadding) != data {
			t.Errorf("expect %+v: unPadding %+v != data %+v", []byte(expect), unPadding, []byte(data))
		}
	}
}

// go test -v -cover -run=^TestPKCS5$
func TestPKCS5(t *testing.T) {
	padder := PKCS5()

	blockSize := 8
	cases := map[string]string{
		string([]byte{}):                       string([]byte{8, 8, 8, 8, 8, 8, 8, 8}),
		string([]byte{1, 2, 3, 4, 5}):          string([]byte{1, 2, 3, 4, 5, 3, 3, 3}),
		string([]byte{1, 2, 3, 4, 5, 6, 7, 8}): string([]byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8}),
	}

	for data, expect := range cases {
		padding := padder.Padding([]byte(data), blockSize)
		if string(padding) != expect {
			t.Errorf("data %+v: padding %+v != expect %s", []byte(data), padding, []byte(expect))
		}
	}

	for data, expect := range cases {
		unPadding, err := padder.UnPadding([]byte(expect), blockSize)
		if err != nil {
			t.Error(err)
		}

		if string(unPadding) != data {
			t.Errorf("expect %+v: unPadding %+v != data %+v", []byte(expect), unPadding, []byte(data))
		}
	}
}

// go test -v -cover -run=^TestPKCS7$
func TestPKCS7(t *testing.T) {
	padder := PKCS7()

	blockSize := 8
	cases := map[string]string{
		string([]byte{}):                       string([]byte{8, 8, 8, 8, 8, 8, 8, 8}),
		string([]byte{1, 2, 3, 4, 5}):          string([]byte{1, 2, 3, 4, 5, 3, 3, 3}),
		string([]byte{1, 2, 3, 4, 5, 6, 7, 8}): string([]byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8}),
	}

	for data, expect := range cases {
		padding := padder.Padding([]byte(data), blockSize)
		if string(padding) != expect {
			t.Errorf("data %+v: padding %+v != expect %s", []byte(data), padding, []byte(expect))
		}
	}

	for data, expect := range cases {
		unPadding, err := padder.UnPadding([]byte(expect), blockSize)
		if err != nil {
			t.Error(err)
		}

		if string(unPadding) != data {
			t.Errorf("expect %+v: unPadding %+v != data %+v", []byte(expect), unPadding, []byte(data))
		}
	}
}
