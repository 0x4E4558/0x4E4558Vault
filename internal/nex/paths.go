package nex

import (
	"errors"
	"path"
	"strings"
)

func NormalizeVaultRelPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	p = strings.ReplaceAll(p, "\\", "/")
	if p == "" {
		return "", errors.New("empty vault path")
	}
	if strings.ContainsRune(p, '\x00') {
		return "", errors.New("NUL in path")
	}
	p = path.Clean(p)
	if p == "." || strings.HasPrefix(p, "/") || p == ".." || strings.HasPrefix(p, "../") {
		return "", errors.New("path must be relative and not escape the vault")
	}
	return p, nil
}
