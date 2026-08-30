//go:build unix

package cli

import (
	"fmt"
	"io"
	"syscall"
)

// execProcess replaces the current process with path so signals and the exit
// code pass straight through. It only returns on failure. The child starts in
// the directory the user ran envc from.
func execProcess(path string, argv, env []string, _ io.Reader, _, _ io.Writer) error {
	if err := syscall.Exec(path, argv, env); err != nil {
		return fmt.Errorf("run: exec %s: %w", path, err)
	}
	return nil
}
