//go:build windows
// +build windows

package variables_test

import (
	"syscall"

	"golang.org/x/sys/windows"
)

const (
	FILE_ATTRIBUTE_HIDDEN     = windows.FILE_ATTRIBUTE_HIDDEN
	FILE_ATTRIBUTE_SYSTEM     = windows.FILE_ATTRIBUTE_SYSTEM
	FILE_ATTRIBUTE_COMPRESSED = windows.FILE_ATTRIBUTE_COMPRESSED
	FILE_ATTRIBUTE_ENCRYPTED  = windows.FILE_ATTRIBUTE_ENCRYPTED
)

func windowsFileAttributeData(fileAttrs uint32) interface{} {
	return &syscall.Win32FileAttributeData{
		FileAttributes: fileAttrs,
	}
}
