//go:build unix

package securebytes

import "golang.org/x/sys/unix"

// SetRlimitHooks replaces the rlimit bridges for the duration of a test.
// Returns a cleanup function that restores the originals.
func SetRlimitHooks(get, set func(int, *unix.Rlimit) error) func() {
	origGet, origSet := getrlimitFn, setrlimitFn
	getrlimitFn, setrlimitFn = get, set
	return func() { getrlimitFn, setrlimitFn = origGet, origSet }
}
