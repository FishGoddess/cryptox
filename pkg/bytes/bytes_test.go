package bytes

import "testing"

// go test -v -cover -run=^TestCopy$
func TestCopy(t *testing.T) {
	bs := []byte("Hello World")
	newSlice := Copy(bs)

	if string(newSlice) != string(bs) {
		t.Errorf("newSlice %s != bs %s", string(newSlice), string(bs))
	}
}
