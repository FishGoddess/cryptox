package base64

import "testing"

// go test -v -cover -run=^TestEncode$
func TestEncode(t *testing.T) {
	cases := map[string]string{
		"":      "",
		"123":   "MTIz",
		"你好，世界": "5L2g5aW977yM5LiW55WM",
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
		"":                     "",
		"MTIz":                 "123",
		"5L2g5aW977yM5LiW55WM": "你好，世界",
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
