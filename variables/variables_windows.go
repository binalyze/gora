//go:build windows
// +build windows

package variables

import (
	"io/fs"
	"syscall"

	"golang.org/x/sys/windows"
)

func hasFileAttr(info fs.FileInfo, attr uint32) bool {
	if info == nil {
		return false
	}
	fileAttrs, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok || fileAttrs == nil {
		return false
	}
	return fileAttrs.FileAttributes&attr != 0
}

func varFileHiddenFunc(sCtx ScanContext) (interface{}, error) {
	return hasFileAttr(sCtx.FileInfo(), windows.FILE_ATTRIBUTE_HIDDEN), nil
}

func varFileSystemFunc(sCtx ScanContext) (interface{}, error) {
	return hasFileAttr(sCtx.FileInfo(), windows.FILE_ATTRIBUTE_SYSTEM), nil
}

func varFileCompressedFunc(sCtx ScanContext) (interface{}, error) {
	return hasFileAttr(sCtx.FileInfo(), windows.FILE_ATTRIBUTE_COMPRESSED), nil
}

func varFileEncryptedFunc(sCtx ScanContext) (interface{}, error) {
	return hasFileAttr(sCtx.FileInfo(), windows.FILE_ATTRIBUTE_ENCRYPTED), nil
}

func varProcessSessionIdFunc(sCtx ScanContext) (interface{}, error) {
	pid := sCtx.Pid()
	if pid <= 0 {
		return nil, nil
	}

	var sessionId uint32
	err := windows.ProcessIdToSessionId(uint32(pid), &sessionId)
	if err != nil {
		return nil, err
	}
	return int64(sessionId), nil
}
