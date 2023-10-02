package variables

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/djherbis/times"
)

type (

	// Variables holds the list of applicable variables to define external variables for yara compiler and scanner, and
	// it provides methods to set values for the yara compiler and scanner.
	Variables struct {
		list []VariableType
	}

	ProcessInfo interface {
		Ppid() (int32, error)
		Username() (string, error)
		NameWithContext(context.Context) (string, error)
		CmdlineWithContext(context.Context) (string, error)
	}

	// ScanContext is an interface that wraps the methods required to calculate variable values for yara scanner.
	ScanContext interface {
		Context() context.Context
		FilePath() string
		FileInfo() fs.FileInfo
		Pid() int
		ProcessInfo() ProcessInfo
		InFileSystem() bool
		InProcess() bool
		HandleValueError(VariableDefiner, VariableType, error) error
	}

	// VariableDefiner is an interface that wraps the DefineVariable method which is implemented by yara compiler and
	// scanner. It is defined as an interface to remove cgo dependency for this package.
	VariableDefiner interface {
		DefineVariable(string, interface{}) error
	}

	// Valuer is an interface that wraps Value method. Value method returns the calculated value of a variable or an
	// error. Variables' Valuer implementation must be registered to Valuers global to be seen by the
	// Variables.DefineScannerVariables method.
	Valuer interface {
		Value(ScanContext) (interface{}, error)
	}

	// ValueFunc is an helper type to implement Valuer interface using a function.
	ValueFunc func(ScanContext) (interface{}, error)

	// VariableType represents an external variable for yara. VariableType's underlying type is an integer to be able to
	// use slices/arrays for faster access.
	VariableType byte
	// MetaType represents a metadata of a VariableType.
	MetaType byte
)

// Variable types.
// L = Linux, W = Windows, D = Darwin, A = AIX

const (
	_ VariableType = iota
	//                       | Name                 | OS   | Type    | Default | Description                                                   |
	//                       |----------------------|------|---------|---------|---------------------------------------------------------------|
	VarOs                 // | os                   | LWDA | String  | ""      | Operating system name, linux, windows, darwin or aix |
	VarOsLinux            // | os_linux             | LWDA | Boolean | false   | If operating system is linux, its value is true |
	VarOsWindows          // | os_windows           | LWDA | Boolean | false   | If operating system is Windows, its value is true |
	VarOsDarwin           // | os_darwin            | LWDA | Boolean | false   | If operating system is Darwin/macOS, its value is true |
	VarOsAIX              // | os_aix               | LWDA | Boolean | false   | If operating system is AIX, its value is true |
	VarInFileSystem       // | in_filesystem        | LWDA | Boolean | false   | Determines whether the current scan context is running for the file system. |
	VarInProcess          // | in_process           | LWDA | Boolean | false   | Determines whether the current scan context is running for the processes. |
	VarTimeNow            // | time_now             | LWDA | Integer | 0       | Current time in YYYYMMDDHHMMSS format |
	VarFilePath           // | file_path            | LWDA | String  | ""      | Path of the file |
	VarFileName           // | file_name            | LWDA | String  | ""      | Name of the file including extension. Example: document.docx |
	VarFileExtension      // | file_extension       | LWDA | String  | ""      | Extension of the file without leading dot. Example: docx |
	VarFileReadonly       // | file_readonly        | LWDA | Boolean | false   | If it is a readonly file, its value is true |
	VarFileHidden         // | file_hidden          | LWDA | Boolean | false   | If it is a hidden file, its value is true |
	VarFileSystem         // | file_system          |  W   | Boolean | false   | If it is a system file, its value is true |
	VarFileCompressed     // | file_compressed      |  W   | Boolean | false   | If it is a compressed file, its value is true |
	VarFileEncrypted      // | file_encrypted       |  W   | Boolean | false   | If it is an encrypted file, its value is true |
	VarFileModifiedTime   // | file_modified_time   | LWDA | Integer | 0       | File's modification time in YYYYMMDDHHMMSS format |
	VarFileAccessedTime   // | file_accessed_time   | LWDA | Integer | 0       | File's access time in YYYYMMDDHHMMSS format |
	VarFileChangedTime    // | file_changed_time    | L DA | Integer | 0       | File's change time in YYYYMMDDHHMMSS format |
	VarFileBirthTime      // | file_birth_time      |  WD  | Integer | 0       | File's birth time in YYYYMMDDHHMMSS format |
	VarProcessId          // | process_id           | LWDA | Integer | 0	      | Process's id |
	VarProcessParentId    // | process_parent_id    | LWDA | Integer | 0       | Parent process id |
	VarProcessUserName    // | process_user_name    | LWDA | String  | ""      | Process's user name. Windows format: <computer name or domain name>\<user name> |
	VarProcessUserSid     // | process_user_sid     | LWDA | String  | ""      | Process's user SID. This returns UID of the user as string on Unixes. |
	VarProcessSessionId   // | process_session_id   | LWDA | Integer | 0       | Process's session id |
	VarProcessName        // | process_name         | LWDA | String  | ""      | Process's name |
	VarProcessPath        // | process_path         | LWDA | String  | ""      | Process's path |
	VarProcessCommandLine // | process_command_line | LWDA | String  | ""      | Process's command line |
	typeEnd
)

// Meta types.
const (
	MetaBool MetaType = 1 << iota
	MetaInt
	MetaFloat
	MetaString
)

var (
	// varNames holds the string names of variables.
	varNames = [typeEnd]string{
		VarOs:                 "os",
		VarOsLinux:            "os_linux",
		VarOsWindows:          "os_windows",
		VarOsDarwin:           "os_darwin",
		VarOsAIX:              "os_aix",
		VarInFileSystem:       "in_filesystem",
		VarInProcess:          "in_process",
		VarTimeNow:            "time_now",
		VarFilePath:           "file_path",
		VarFileName:           "file_name",
		VarFileExtension:      "file_extension",
		VarFileReadonly:       "file_readonly",
		VarFileHidden:         "file_hidden",
		VarFileSystem:         "file_system",
		VarFileCompressed:     "file_compressed",
		VarFileEncrypted:      "file_encrypted",
		VarFileModifiedTime:   "file_modified_time",
		VarFileAccessedTime:   "file_accessed_time",
		VarFileChangedTime:    "file_changed_time",
		VarFileBirthTime:      "file_birth_time",
		VarProcessId:          "process_id",
		VarProcessParentId:    "process_parent_id",
		VarProcessUserName:    "process_user_name",
		VarProcessUserSid:     "process_user_sid",
		VarProcessSessionId:   "process_session_id",
		VarProcessName:        "process_name",
		VarProcessPath:        "process_path",
		VarProcessCommandLine: "process_command_line",
	}

	// varMetas holds the metadata of all variables.
	varMetas = [typeEnd]MetaType{
		VarOs:                 MetaString,
		VarOsLinux:            MetaBool,
		VarOsWindows:          MetaBool,
		VarOsDarwin:           MetaBool,
		VarOsAIX:              MetaBool,
		VarInFileSystem:       MetaBool,
		VarInProcess:          MetaBool,
		VarTimeNow:            MetaInt,
		VarFilePath:           MetaString,
		VarFileName:           MetaString,
		VarFileExtension:      MetaString,
		VarFileReadonly:       MetaBool,
		VarFileHidden:         MetaBool,
		VarFileSystem:         MetaBool,
		VarFileCompressed:     MetaBool,
		VarFileEncrypted:      MetaBool,
		VarFileModifiedTime:   MetaInt,
		VarFileAccessedTime:   MetaInt,
		VarFileChangedTime:    MetaInt,
		VarFileBirthTime:      MetaInt,
		VarProcessId:          MetaInt,
		VarProcessParentId:    MetaInt,
		VarProcessUserName:    MetaString,
		VarProcessUserSid:     MetaString,
		VarProcessSessionId:   MetaInt,
		VarProcessName:        MetaString,
		VarProcessPath:        MetaString,
		VarProcessCommandLine: MetaString,
	}

	// Valuers holds the Valuer implementations of all variables.
	Valuers = [typeEnd]Valuer{
		VarOs:                 ValueFunc(varOsFunc),
		VarOsLinux:            ValueFunc(varOsLinuxFunc),
		VarOsWindows:          ValueFunc(varOsWindowsFunc),
		VarOsDarwin:           ValueFunc(varOsDarwinFunc),
		VarOsAIX:              ValueFunc(varOsAIX),
		VarInFileSystem:       ValueFunc(varInFileSystemFunc),
		VarInProcess:          ValueFunc(varInProcessFunc),
		VarTimeNow:            ValueFunc(varTimeNowFunc),
		VarFilePath:           ValueFunc(varFilePathFunc),
		VarFileName:           ValueFunc(varFileNameFunc),
		VarFileExtension:      ValueFunc(varFileExtensionFunc),
		VarFileReadonly:       ValueFunc(varFileReadonlyFunc),
		VarFileHidden:         ValueFunc(varFileHiddenFunc),
		VarFileSystem:         ValueFunc(varFileSystemFunc),
		VarFileCompressed:     ValueFunc(varFileCompressedFunc),
		VarFileEncrypted:      ValueFunc(varFileEncryptedFunc),
		VarFileModifiedTime:   ValueFunc(varFileModifiedTimeFunc),
		VarFileAccessedTime:   ValueFunc(varFileAccessedTimeFunc),
		VarFileChangedTime:    ValueFunc(varFileChangedTimeFunc),
		VarFileBirthTime:      ValueFunc(varFileBirthTimeFunc),
		VarProcessId:          ValueFunc(varProcessIdFunc),
		VarProcessParentId:    ValueFunc(varProcessParentIdFunc),
		VarProcessUserName:    ValueFunc(varProcessUserNameFunc),
		VarProcessUserSid:     ValueFunc(varProcessUserSidFunc),
		VarProcessSessionId:   ValueFunc(varProcessSessionIdFunc),
		VarProcessName:        ValueFunc(varProcessNameFunc),
		VarProcessPath:        ValueFunc(varFilePathFunc), // FilePath holds the process's path as well.
		VarProcessCommandLine: ValueFunc(varProcessCommandLineFunc),
	}
)

const intFileTimeLayout = "20060102150405"

// List returns the list of all available variables. It creates a new slice at every call.
func List() []VariableType {
	list := make([]VariableType, 0, len(varNames)-1)
	for v := 1; v < len(varNames); v++ {
		list = append(list, VariableType(v))
	}
	return list
}

// Value implements Valuer interface.
func (fn ValueFunc) Value(sCtx ScanContext) (interface{}, error) {
	return fn(sCtx)
}

// String implements the fmt.Stringer interface and returns the string representation of a VariableType.
func (v VariableType) String() string {
	if v < typeEnd {
		return varNames[v]
	}
	return ""
}

// Meta returns the meta data of the variable.
func (v VariableType) Meta() MetaType {
	if v < typeEnd {
		return varMetas[v]
	}
	return 0
}

// InitVariables sets Variables instance's applicable variables.
func (vr *Variables) InitVariables(vars []VariableType) {
	vr.setVariables(vars)
}

// DefineCompilerVariables defines the already set variables to the given compiler using their default zero values.
func (vr *Variables) DefineCompilerVariables(compiler VariableDefiner) (err error) {
	for _, vid := range vr.list {
		err = defineDefaultValue(vid, compiler)
		if err != nil {
			return
		}
	}
	return
}

// DefineScannerVariables defines the already set variables to the given scanner using their calculated values using
// their Valuer implementations. Returning error from Valuer's Value method should be handled by the given
// ScanContext.HandleValueError.
func (vr *Variables) DefineScannerVariables(sCtx ScanContext, scanner VariableDefiner) error {
	for _, vid := range vr.list {
		valuer := Valuers[vid]
		value, err := valuer.Value(sCtx)

		if err != nil || value == nil {
			if e := defineDefaultValue(vid, scanner); e != nil {
				if err != nil {
					return fmt.Errorf("%s: %w", err, e)
				}
				return e
			}
			if err != nil {
				if err = sCtx.HandleValueError(scanner, vid, err); err != nil {
					return err
				}
			}
			continue
		}

		err = scanner.DefineVariable(vid.String(), value)
		if err != nil {
			return err
		}
	}
	return nil
}

// Copy creates a new instance of Variables by deeply copying.
// This should be used to create new Variables instances for each scanner thread.
func (vr *Variables) Copy() *Variables {
	return &Variables{
		list: vr.Variables(),
	}
}

// Variables returns a copy of variables list.
func (vr *Variables) Variables() []VariableType {
	list := make([]VariableType, len(vr.list))
	copy(list, vr.list)
	return list
}

func (vr *Variables) setVariables(vars []VariableType) {
	vr.list = []VariableType{}
	vmap := make(map[VariableType]struct{}, typeEnd) // deduplicate if any.

	for _, vid := range vars {
		if _, ok := vmap[vid]; ok {
			continue
		}

		vr.list = append(vr.list, vid)
		vmap[vid] = struct{}{}
	}
}

func defineDefaultValue(vid VariableType, def VariableDefiner) error {
	var (
		meta   = vid.Meta()
		defVal interface{}
	)

	if meta&MetaString != 0 {
		defVal = ""
	} else if meta&MetaInt != 0 {
		defVal = int64(0)
	} else if meta&MetaBool != 0 {
		defVal = false
	} else if meta&MetaFloat != 0 {
		defVal = float64(0)
	} else {
		return fmt.Errorf("unknown variable: %[1]s(%[1]d)", vid)
	}
	return def.DefineVariable(vid.String(), defVal)
}

// Define values not to allocate.
var (
	vOsValueWindows interface{} = "windows"
	vOsValueLinux   interface{} = "linux"
	vOsValueDarwin  interface{} = "darwin"
	vOsValueAIX     interface{} = "aix"
)

func varOsFunc(_ ScanContext) (interface{}, error) {
	switch runtime.GOOS {
	case "windows":
		return vOsValueWindows, nil
	case "linux":
		return vOsValueLinux, nil
	case "darwin":
		return vOsValueDarwin, nil
	case "aix":
		return vOsValueAIX, nil
	default:
		return runtime.GOOS, nil
	}
}

//lint:ignore U1000 it is used in platform specific files.
func noopVarFunc(_ ScanContext) (interface{}, error) { return nil, nil } // nolint

func varOsLinuxFunc(_ ScanContext) (interface{}, error) {
	return runtime.GOOS == "linux", nil
}

func varOsWindowsFunc(_ ScanContext) (interface{}, error) {
	return runtime.GOOS == "windows", nil
}

func varOsDarwinFunc(_ ScanContext) (interface{}, error) {
	return runtime.GOOS == "darwin", nil
}

func varOsAIX(_ ScanContext) (interface{}, error) {
	return runtime.GOOS == "aix", nil
}

func varTimeNowFunc(_ ScanContext) (interface{}, error) {
	return intTimeHelper(time.Now())
}

func varInFileSystemFunc(sCtx ScanContext) (interface{}, error) {
	return sCtx.InFileSystem(), nil
}

func varInProcessFunc(sCtx ScanContext) (interface{}, error) {
	return sCtx.InProcess(), nil
}

func varFilePathFunc(sCtx ScanContext) (interface{}, error) {
	p := sCtx.FilePath()
	if p == "" {
		return "", nil
	}
	p = filepath.Clean(p)
	return p, nil
}

func varFileNameFunc(sCtx ScanContext) (interface{}, error) {
	p, err := varFilePathFunc(sCtx)
	if err != nil || p == nil || p.(string) == "" {
		return p, err
	}
	base := filepath.Base(p.(string))
	if base == "." {
		return "", nil
	}
	return base, nil
}

func varFileExtensionFunc(sCtx ScanContext) (interface{}, error) {
	p, err := varFilePathFunc(sCtx)
	path := p.(string)
	if err != nil || p == nil || path == "" {
		return p, err
	}
	if strings.HasPrefix(path, ".") && strings.Count(path, ".") == 1 {
		return "", nil
	}
	ext := filepath.Ext(path)
	return strings.TrimPrefix(ext, "."), nil
}

func varFileReadonlyFunc(sCtx ScanContext) (interface{}, error) {
	info := sCtx.FileInfo()
	if info == nil {
		return nil, nil
	}
	// Check write bit is not set to determine it is readonly. This also works in Windows.
	// For Windows, Permission bits are derived from file attributes.
	// Note that we check if file is readonly for all users for Unixes.
	return info.Mode().Perm()&0222 == 0, nil
}

func intTimeHelper(t time.Time) (interface{}, error) {
	s := t.Format(intFileTimeLayout)
	return strconv.ParseInt(s, 10, 64)
}

func varFileModifiedTimeFunc(sCtx ScanContext) (interface{}, error) {
	info := sCtx.FileInfo()
	if info == nil {
		return nil, nil
	}
	return intTimeHelper(info.ModTime())
}

func varFileAccessedTimeFunc(sCtx ScanContext) (interface{}, error) {
	info := sCtx.FileInfo()
	if info == nil {
		return nil, nil
	}
	ts := times.Get(info)
	return intTimeHelper(ts.AccessTime())
}

func varFileChangedTimeFunc(sCtx ScanContext) (interface{}, error) {
	info := sCtx.FileInfo()
	if info == nil {
		return nil, nil
	}
	ts := times.Get(info)
	if ts.HasChangeTime() {
		return intTimeHelper(ts.ChangeTime())
	}
	return nil, nil
}

func varFileBirthTimeFunc(sCtx ScanContext) (interface{}, error) {
	info := sCtx.FileInfo()
	if info == nil {
		return nil, nil
	}
	ts := times.Get(info)
	if ts.HasBirthTime() {
		return intTimeHelper(ts.BirthTime())
	}
	return nil, nil
}

func varProcessIdFunc(sCtx ScanContext) (interface{}, error) {
	return int64(sCtx.Pid()), nil
}

func varProcessParentIdFunc(sCtx ScanContext) (interface{}, error) {
	proc := sCtx.ProcessInfo()
	if proc == nil {
		return nil, nil
	}
	ppid, err := proc.Ppid()
	if err != nil {
		return nil, err
	}
	return int64(ppid), nil
}

func varProcessUserNameFunc(sCtx ScanContext) (interface{}, error) {
	proc := sCtx.ProcessInfo()
	if proc == nil {
		return nil, nil
	}
	return proc.Username()
}

func varProcessNameFunc(sCtx ScanContext) (interface{}, error) {
	proc := sCtx.ProcessInfo()
	if proc == nil {
		return nil, nil
	}
	return proc.NameWithContext(sCtx.Context())
}

func varProcessCommandLineFunc(sCtx ScanContext) (interface{}, error) {
	proc := sCtx.ProcessInfo()
	if proc == nil {
		return nil, nil
	}
	return proc.CmdlineWithContext(sCtx.Context())
}
