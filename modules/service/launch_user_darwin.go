//go:build darwin

package service

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

func resolveLaunchdUser() (launchdUser, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return launchdUser{}, fmt.Errorf("determine process home directory: %w", err)
	}
	process := launchdUser{uid: os.Getuid(), home: home}
	if process.uid != 0 {
		return process, nil
	}

	info, err := os.Stat("/dev/console")
	if err != nil {
		return launchdUser{}, fmt.Errorf("identify logged-in GUI user: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return launchdUser{}, fmt.Errorf("identify logged-in GUI user: unsupported console ownership")
	}
	consoleUID := int(stat.Uid)
	consoleAccount, err := user.LookupId(strconv.Itoa(consoleUID))
	if err != nil {
		return launchdUser{}, fmt.Errorf("look up logged-in GUI user %d: %w", consoleUID, err)
	}
	return selectLaunchdUser(process, launchdUser{uid: consoleUID, home: consoleAccount.HomeDir})
}
