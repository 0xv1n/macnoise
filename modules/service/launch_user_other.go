//go:build !darwin

package service

import (
	"fmt"
	"os"
)

func resolveLaunchdUser() (launchdUser, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return launchdUser{}, fmt.Errorf("determine process home directory: %w", err)
	}
	return launchdUser{uid: os.Getuid(), home: home}, nil
}
