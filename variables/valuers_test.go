package variables_test

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v3/process"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	. "github.com/binalyze/gora/variables"
)

type valExpectFunc = func(t *testing.T, got interface{})

func TestValuers(t *testing.T) {

	testCases := []struct {
		vid    VariableType
		expect interface{}
		c      *scanContextMock
	}{
		{vid: VarOs, expect: runtime.GOOS},
		{vid: VarOsLinux, expect: runtime.GOOS == "linux"},
		{vid: VarOsWindows, expect: runtime.GOOS == "windows"},
		{
			vid: VarTimeNow,
			expect: func(t *testing.T, got interface{}) {
				require.Greater(t, got.(int64), int64(0))
			},
		},
		{
			vid:    VarFilePath,
			expect: "",
			c: func() *scanContextMock {
				c := new(scanContextMock)
				c.On("FilePath").Return("").Times(1)
				return c
			}(),
		},
		{
			vid:    VarFilePath,
			expect: "abc",
			c: func() *scanContextMock {
				c := new(scanContextMock)
				c.On("FilePath").Return("abc").Times(1)
				return c
			}(),
		},
		{
			vid:    VarFileName,
			expect: "c",
			c: func() *scanContextMock {
				c := new(scanContextMock)
				c.On("FilePath").Return(filepath.Join("a", "b", "c")).Times(1)
				return c
			}(),
		},
		{
			vid:    VarFileExtension,
			expect: "",
			c: func() *scanContextMock {
				c := new(scanContextMock)
				c.On("FilePath").Return(filepath.Join("a", "b", "c")).Times(1)
				return c
			}(),
		},
		{
			vid:    VarFileExtension,
			expect: "txt",
			c: func() *scanContextMock {
				c := new(scanContextMock)
				c.On("FilePath").Return(filepath.Join("a", "b", "c.txt")).Times(1)
				return c
			}(),
		},
		{
			vid:    VarFileReadonly,
			expect: true,
			c: func() *scanContextMock {
				p := filepath.Join(t.TempDir(), "c.txt")
				err := os.WriteFile(p, nil, 0444)
				require.NoError(t, err)

				info, err := os.Stat(p)
				require.NoError(t, err)

				c := new(scanContextMock)
				c.On("FileInfo").Return(info).Times(1)
				return c
			}(),
		},
		{
			vid:    VarFileReadonly,
			expect: false,
			c: func() *scanContextMock {
				p := filepath.Join(t.TempDir(), "c.txt")
				err := os.WriteFile(p, nil, 0666)
				require.NoError(t, err)

				info, err := os.Stat(p)
				require.NoError(t, err)

				c := new(scanContextMock)
				c.On("FileInfo").Return(info).Times(1)
				return c
			}(),
		},
		{
			vid:    VarFileHidden,
			expect: true,
			c: func() *scanContextMock {
				c := new(scanContextMock)
				if runtime.GOOS != "windows" {
					c.On("FilePath").Return(".c.txt").Times(1)
				} else {
					mi := new(mockFileInfo)
					mi.On("Sys").Return(windowsFileAttributeData(FILE_ATTRIBUTE_HIDDEN)).Times(1)
					c.On("FileInfo").Return(mi).Times(1)
				}
				return c
			}(),
		},
		{
			vid:    VarFileHidden,
			expect: false,
			c: func() *scanContextMock {
				c := new(scanContextMock)
				if runtime.GOOS != "windows" {
					c.On("FilePath").Return("c.txt").Times(1)
				} else {
					mi := new(mockFileInfo)
					mi.On("Sys").Return(windowsFileAttributeData(0))
					c.On("FileInfo").Return(mi).Times(1)
				}
				return c
			}(),
		},
		{
			vid: VarFileSystem,
			expect: func(t *testing.T, got interface{}) {
				if runtime.GOOS != "windows" {
					require.Nil(t, got)
				} else {
					require.True(t, got.(bool))
				}
			},
			c: func() *scanContextMock {
				c := new(scanContextMock)
				if runtime.GOOS == "windows" {
					mi := new(mockFileInfo)
					mi.On("Sys").Return(windowsFileAttributeData(FILE_ATTRIBUTE_SYSTEM)).Times(1)
					c.On("FileInfo").Return(mi).Times(1)
				}
				return c
			}(),
		},
		{
			vid: VarFileSystem,
			expect: func(t *testing.T, got interface{}) {
				if runtime.GOOS != "windows" {
					require.Nil(t, got)
				} else {
					require.False(t, got.(bool))
				}
			},
			c: func() *scanContextMock {
				c := new(scanContextMock)
				if runtime.GOOS == "windows" {
					mi := new(mockFileInfo)
					mi.On("Sys").Return(windowsFileAttributeData(0)).Times(1)
					c.On("FileInfo").Return(mi).Times(1)
				}
				return c
			}(),
		},
		{
			vid: VarFileCompressed,
			expect: func(t *testing.T, got interface{}) {
				if runtime.GOOS != "windows" {
					require.Nil(t, got)
				} else {
					require.True(t, got.(bool))
				}
			},
			c: func() *scanContextMock {
				c := new(scanContextMock)
				if runtime.GOOS == "windows" {
					mi := new(mockFileInfo)
					mi.On("Sys").Return(windowsFileAttributeData(FILE_ATTRIBUTE_COMPRESSED)).Times(1)
					c.On("FileInfo").Return(mi).Times(1)
				}
				return c
			}(),
		},
		{
			vid: VarFileCompressed,
			expect: func(t *testing.T, got interface{}) {
				if runtime.GOOS != "windows" {
					require.Nil(t, got)
				} else {
					require.False(t, got.(bool))
				}
			},
			c: func() *scanContextMock {
				c := new(scanContextMock)
				if runtime.GOOS == "windows" {
					mi := new(mockFileInfo)
					mi.On("Sys").Return(windowsFileAttributeData(0)).Times(1)
					c.On("FileInfo").Return(mi).Times(1)
				}
				return c
			}(),
		},
		{
			vid: VarFileEncrypted,
			expect: func(t *testing.T, got interface{}) {
				if runtime.GOOS != "windows" {
					require.Nil(t, got)
				} else {
					require.True(t, got.(bool))
				}
			},
			c: func() *scanContextMock {
				c := new(scanContextMock)
				if runtime.GOOS == "windows" {
					mi := new(mockFileInfo)
					mi.On("Sys").Return(windowsFileAttributeData(FILE_ATTRIBUTE_ENCRYPTED)).Times(1)
					c.On("FileInfo").Return(mi).Times(1)
				}
				return c
			}(),
		},
		{
			vid: VarFileEncrypted,
			expect: func(t *testing.T, got interface{}) {
				if runtime.GOOS != "windows" {
					require.Nil(t, got)
				} else {
					require.False(t, got.(bool))
				}
			},
			c: func() *scanContextMock {
				c := new(scanContextMock)
				if runtime.GOOS == "windows" {
					mi := new(mockFileInfo)
					mi.On("Sys").Return(windowsFileAttributeData(0)).Times(1)
					c.On("FileInfo").Return(mi).Times(1)
				}
				return c
			}(),
		},
		{
			vid:    VarFileModifiedTime,
			expect: nil,
			c: func() *scanContextMock {
				c := new(scanContextMock)
				c.On("FileInfo").Return(nil).Times(1)
				return c
			}(),
		},
		{
			vid: VarFileModifiedTime,
			expect: func(t *testing.T, got interface{}) {
				require.NotZero(t, got)
			},
			c: func() *scanContextMock {
				_, info := touchFile(t, "c.txt")
				c := new(scanContextMock)
				c.On("FileInfo").Return(info).Times(1)
				return c
			}(),
		},
		{
			vid:    VarFileAccessedTime,
			expect: nil,
			c: func() *scanContextMock {
				c := new(scanContextMock)
				c.On("FileInfo").Return(nil).Times(1)
				return c
			}(),
		},
		{
			vid: VarFileAccessedTime,
			expect: func(t *testing.T, got interface{}) {
				require.NotZero(t, got)
			},
			c: func() *scanContextMock {
				_, info := touchFile(t, "c.txt")
				c := new(scanContextMock)
				c.On("FileInfo").Return(info).Times(1)
				return c
			}(),
		},
		{
			vid:    VarFileChangedTime,
			expect: nil,
			c: func() *scanContextMock {
				c := new(scanContextMock)
				c.On("FileInfo").Return(nil).Times(1)
				return c
			}(),
		},
		{
			vid: VarFileChangedTime,
			expect: func(t *testing.T, got interface{}) {
				if runtime.GOOS != "windows" {
					require.NotZero(t, got)
				} else {
					require.Nil(t, got)
				}
			},
			c: func() *scanContextMock {
				_, info := touchFile(t, "c.txt")
				c := new(scanContextMock)
				c.On("FileInfo").Return(info).Times(1)
				return c
			}(),
		},
		{
			vid:    VarFileBirthTime,
			expect: nil,
			c: func() *scanContextMock {
				c := new(scanContextMock)
				c.On("FileInfo").Return(nil).Times(1)
				return c
			}(),
		},
		{
			vid: VarFileBirthTime,
			expect: func(t *testing.T, got interface{}) {
				if runtime.GOOS == "linux" {
					require.Nil(t, got) // No birth time for Linux.
				} else {
					require.NotZero(t, got)
				}
			},
			c: func() *scanContextMock {
				_, info := touchFile(t, "c.txt")
				c := new(scanContextMock)
				c.On("FileInfo").Return(info).Times(1)
				return c
			}(),
		},
		// Process tests
		{
			vid:    VarProcessId,
			expect: int64(1),
			c: func() *scanContextMock {
				c := new(scanContextMock)
				c.On("Pid").Return(int(1)).Times(1)
				return c
			}(),
		},
		{
			vid:    VarProcessParentId,
			expect: nil,
			c: func() *scanContextMock {
				c := new(scanContextMock)
				c.On("ProcessInfo").Return(nil).Times(1)
				return c
			}(),
		},
		{
			vid: VarProcessParentId,
			expect: func(t *testing.T, got interface{}) {
				ppid := os.Getppid()
				require.Equal(t, int64(ppid), got)
			},
			c: func() *scanContextMock {
				proc, err := process.NewProcess(int32(os.Getpid()))
				require.NoError(t, err)

				c := new(scanContextMock)
				c.On("ProcessInfo").Return(proc).Times(1)
				return c
			}(),
		},
		{
			vid:    VarProcessUserName,
			expect: nil,
			c: func() *scanContextMock {
				c := new(scanContextMock)
				c.On("ProcessInfo").Return(nil).Times(1)
				return c
			}(),
		},
		{
			vid: VarProcessUserName,
			expect: func(t *testing.T, got interface{}) {
				require.NotNil(t, got)
			},
			c: func() *scanContextMock {
				proc, err := process.NewProcess(int32(os.Getpid()))
				require.NoError(t, err)

				c := new(scanContextMock)
				c.On("ProcessInfo").Return(proc).Times(1)
				return c
			}(),
		},
		{
			vid:    VarProcessUserSid,
			expect: nil,
			c: func() *scanContextMock {
				c := new(scanContextMock)
				c.On("ProcessInfo").Return(nil).Times(1)
				return c
			}(),
		},
		{
			vid: VarProcessUserSid,
			expect: func(t *testing.T, got interface{}) {
				require.NotNil(t, got)
			},
			c: func() *scanContextMock {
				proc, err := process.NewProcess(int32(os.Getpid()))
				require.NoError(t, err)

				c := new(scanContextMock)
				c.On("ProcessInfo").Return(proc).Times(1)
				return c
			}(),
		},
		{
			vid:    VarProcessSessionId,
			expect: nil,
			c: func() *scanContextMock {
				c := new(scanContextMock)
				c.On("Pid").Return(int(0)).Times(1)
				return c
			}(),
		},
		{
			vid: VarProcessSessionId,
			expect: func(t *testing.T, got interface{}) {
				require.NotNil(t, got)
			},
			c: func() *scanContextMock {
				c := new(scanContextMock)
				c.On("Pid").Return(os.Getpid()).Times(1)
				return c
			}(),
		},
		{
			vid:    VarProcessName,
			expect: nil,
			c: func() *scanContextMock {
				c := new(scanContextMock)
				c.On("ProcessInfo").Return(nil).Times(1)
				return c
			}(),
		},
		{
			vid: VarProcessName,
			expect: func(t *testing.T, got interface{}) {
				require.NotNil(t, got)
			},
			c: func() *scanContextMock {
				proc, err := process.NewProcess(int32(os.Getpid()))
				require.NoError(t, err)

				c := new(scanContextMock)
				c.On("Context").Return(context.Background()).Times(1)
				c.On("ProcessInfo").Return(proc).Times(1)
				return c
			}(),
		},
		{
			vid:    VarProcessPath,
			expect: "",
			c: func() *scanContextMock {
				c := new(scanContextMock)
				c.On("FilePath").Return("").Times(1)
				return c
			}(),
		},
		{
			vid: VarProcessPath,
			expect: func(t *testing.T, got interface{}) {
				p := getAppFilePath()
				require.Equal(t, p, got)
			},
			c: func() *scanContextMock {
				p := getAppFilePath()
				c := new(scanContextMock)
				c.On("FilePath").Return(p).Times(1)
				return c
			}(),
		},
		{
			vid:    VarProcessCommandLine,
			expect: nil,
			c: func() *scanContextMock {
				c := new(scanContextMock)
				c.On("ProcessInfo").Return(nil).Times(1)
				return c
			}(),
		},
		{
			vid: VarProcessCommandLine,
			expect: func(t *testing.T, got interface{}) {
				require.NotEmpty(t, got)
			},
			c: func() *scanContextMock {
				proc, err := process.NewProcess(int32(os.Getpid()))
				require.NoError(t, err)

				c := new(scanContextMock)
				c.On("Context").Return(context.Background()).Times(1)
				c.On("ProcessInfo").Return(proc).Times(1)
				return c
			}(),
		},
	}

	for _, tC := range testCases {
		t.Run(tC.vid.String(), func(t *testing.T) {

			valuer := Valuers[tC.vid]
			value, err := valuer.Value(tC.c)
			require.NoError(t, err)
			if fn, ok := tC.expect.(valExpectFunc); ok {
				fn(t, value)
			} else {
				require.Equal(t, tC.expect, value)
			}
			if tC.c != nil {
				tC.c.AssertExpectations(t)
			}
		})
	}

}

func touchFile(t *testing.T, name string) (path string, info fs.FileInfo) {
	t.Helper()

	path = filepath.Join(t.TempDir(), "c.txt")
	err := os.WriteFile(path, nil, 0777)
	require.NoError(t, err)

	info, err = os.Stat(path)
	require.NoError(t, err)
	return
}

type mockFileInfo struct {
	mock.Mock
}

var _ fs.FileInfo = (*mockFileInfo)(nil)

func (m *mockFileInfo) IsDir() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *mockFileInfo) ModTime() time.Time {
	args := m.Called()
	return args.Get(0).(time.Time)
}

func (m *mockFileInfo) Mode() fs.FileMode {
	args := m.Called()
	return args.Get(0).(fs.FileMode)
}

func (m *mockFileInfo) Name() string {
	args := m.Called()
	return args.String(0)
}

func (m *mockFileInfo) Size() int64 {
	args := m.Called()
	return args.Get(0).(int64)
}

func (m *mockFileInfo) Sys() interface{} {
	args := m.Called()
	return args.Get(0)
}

var appFileOnce sync.Once
var appFile string

func getAppFilePath() string {
	appFileOnce.Do(func() {
		exe, err := os.Executable()
		if err == nil {
			appFile = exe
			return
		}
		appFile = os.Args[0]
	})
	return appFile
}
