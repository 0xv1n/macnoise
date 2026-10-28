package service

import (
	"bytes"

	"github.com/0xv1n/macnoise/internal/ownership"
	"howett.net/plist"
)

func createLaunchdPlist(path, label, program string) (ownership.File, error) {
	plistData := map[string]any{
		"Label":            label,
		"ProgramArguments": []string{program},
		"RunAtLoad":        false,
		"KeepAlive":        false,
	}

	var encoded bytes.Buffer
	enc := plist.NewEncoder(&encoded)
	enc.Indent("\t")
	if err := enc.Encode(plistData); err != nil {
		return ownership.File{}, err
	}
	return ownership.CreateFile(path, encoded.Bytes(), 0o644)
}
