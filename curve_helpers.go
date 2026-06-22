package hdwallet

import "fmt"

// errInvalidKeyLen builds a consistent error for an unexpected key length on one
// of the extended curves.
func errInvalidKeyLen(curve string, got, want int) error {
	return fmt.Errorf("hdwallet: %s: invalid key length %d (want %d)", curve, got, want)
}
