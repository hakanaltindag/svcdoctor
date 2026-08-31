//go:build unix

package secret_test

import "syscall"

// makeFIFO creates a named pipe so the preflight's regular-file requirement can
// be exercised against something that is not one.
//
// A FIFO is the case that matters rather than a curiosity: opening one blocks
// until a writer appears, so a credential reference pointing at one would hang a
// run forever. os.Stat does not block, which is why the check is a stat and not
// an open.
func makeFIFO(path string) error {
	return syscall.Mkfifo(path, 0o600)
}
