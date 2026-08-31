//go:build !unix

package secret_test

import "errors"

// makeFIFO reports that this platform has no named pipes to test against. The
// caller skips.
func makeFIFO(string) error {
	return errors.New("named pipes are not available on this platform")
}
