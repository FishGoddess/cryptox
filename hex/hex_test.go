package hex

import "testing"

// go test -v -cover -run=^TestEncode$
func TestEncode(t *testing.T) {
	cases := map[string]string{
		"":      "",
		"123":   "313233",
		"你好，世界": "e4bda0e5a5bdefbc8ce4b896e7958c",
	}

	for plain, expect := range cases {
		encoded := Encode([]byte(plain))
		if encoded != expect {
			t.Errorf("plain %s: encoded %s != expect %s", plain, encoded, expect)
		}
	}
}

// go test -v -cover -run=^TestDecode$
func TestDecode(t *testing.T) {
	cases := map[string]string{
		"":                               "",
		"313233":                         "123",
		"e4bda0e5a5bdefbc8ce4b896e7958c": "你好，世界",
	}

	for encoded, expect := range cases {
		plain, err := Decode(encoded)
		if err != nil {
			t.Error(err)
		}

		plainStr := string(plain)
		if plainStr != expect {
			t.Errorf("encoded %s: plainStr %s != expect %s", encoded, plainStr, expect)
		}
	}
}
