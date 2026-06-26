//go:build windows

package gate

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
)

func configureCommandProcess(cmd *exec.Cmd) {}

func terminateCommandProcess(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	if err := exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid)).Run(); err == nil {
		return nil
	}
	err := cmd.Process.Kill()
	if errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	return err
}
