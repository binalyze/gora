//go:build linux || darwin
// +build linux darwin

package variables_test

const (
	FILE_ATTRIBUTE_HIDDEN     = 0
	FILE_ATTRIBUTE_SYSTEM     = 0
	FILE_ATTRIBUTE_COMPRESSED = 0
	FILE_ATTRIBUTE_ENCRYPTED  = 0
)

func windowsFileAttributeData(fileAttrs uint32) interface{} { return nil }
