//go:build !unix

package cli

import (
	"errors"
	"fmt"
	"io"
	"os/exec"
)

// execProcess runs path as a child with stdio attached and propagates its
// exit code (there is no execve on this platform). The child starts in the
// directory the user ran envc from.
func execProcess(path string, argv, env []string, stdin io.Reader, stdout, stderr io.Writer) error {
	cmd := exec.Command(path, argv[1:]...)
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return &silentExit{code: ee.ExitCode()}
	}
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}
	return nil
}
