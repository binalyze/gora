//go:build linux || darwin || aix
// +build linux darwin aix

package variables

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func varFileHiddenFunc(sCtx ScanContext) (interface{}, error) {
	return strings.HasPrefix(filepath.Base(sCtx.FilePath()), "."), nil
}

var (
	varFileSystemFunc     = noopVarFunc
	varFileCompressedFunc = noopVarFunc
	varFileEncryptedFunc  = noopVarFunc
)

func varProcessSessionIdFunc(sCtx ScanContext) (interface{}, error) {
	pid := sCtx.Pid()
	if pid <= 0 {
		return nil, nil
	}
	sid, err := unix.Getsid(pid)
	if err != nil {
		return nil, err
	}
	return int64(sid), nil
}
