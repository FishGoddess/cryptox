package bytes

// Copy copies bs to a new byte slice.
func Copy(bs []byte) []byte {
	newSlice := make([]byte, len(bs))
	copy(newSlice, bs)

	return newSlice
}
