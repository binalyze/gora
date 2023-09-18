//go:build linux || darwin || aix
// +build linux darwin aix

package variables

import (
	"os/user"
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

func varProcessUserSidFunc(sCtx ScanContext) (interface{}, error) {
	uname, err := varProcessUserNameFunc(sCtx)
	if err != nil {
		return nil, err
	}
	name, ok := uname.(string)
	if !ok || name == "" {
		return nil, nil
	}
	usr, err := user.Lookup(name)
	if err != nil {
		return nil, err
	}
	return usr.Uid, nil
}
