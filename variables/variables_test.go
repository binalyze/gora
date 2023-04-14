package variables_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"runtime"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	. "github.com/binalyze/gora/variables"
)

var AllVars []VariableType
var AllVarsOnlyProcs []VariableType

func init() {
	AllVars = List()
	for _, vid := range AllVars {
		if vid.Meta()&MetaProcess != 0 && vid.Meta()&MetaFile == 0 {
			AllVarsOnlyProcs = append(AllVarsOnlyProcs, vid)
		}
	}
}

type variableDefinerMock struct {
	mock.Mock
}

var _ VariableDefiner = (*variableDefinerMock)(nil)

func (v *variableDefinerMock) DefineVariable(name string, val interface{}) error {
	args := v.Called(name, val)
	return args.Error(0)
}

type scanContextMock struct {
	mock.Mock
}

var _ ScanContext = (*scanContextMock)(nil)

func (m *scanContextMock) Context() context.Context {
	args := m.Called()
	return args.Get(0).(context.Context)
}

func (m *scanContextMock) FilePath() string {
	args := m.Called()
	return args.String(0)
}

func (m *scanContextMock) FileInfo() fs.FileInfo {
	args := m.Called()
	v, ok := args.Get(0).(fs.FileInfo)
	if ok {
		return v
	}
	return nil
}

func (m *scanContextMock) Pid() int {
	args := m.Called()
	return args.Int(0)
}

func (m *scanContextMock) ProcessInfo() ProcessInfo {
	args := m.Called()
	v, ok := args.Get(0).(ProcessInfo)
	if !ok {
		return nil
	}
	return v
}

func (m *scanContextMock) HandleValueError(VariableDefiner, VariableType, error) error {
	args := m.Called()
	return args.Error(0)
}

func (m *scanContextMock) IsFileSystemContext() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *scanContextMock) IsProcessContext() bool {
	args := m.Called()
	return args.Bool(0)
}

type processInfoMock struct {
	mock.Mock
}

var _ ProcessInfo = (*processInfoMock)(nil)

func (m *processInfoMock) Ppid() (int32, error) {
	args := m.Called()
	return int32(args.Int(0)), args.Error(1)
}

func (m *processInfoMock) Username() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *processInfoMock) NameWithContext(ctx context.Context) (string, error) {
	args := m.Called(ctx)
	return args.String(0), args.Error(1)
}

func (m *processInfoMock) CmdlineWithContext(ctx context.Context) (string, error) {
	args := m.Called(ctx)
	return args.String(0), args.Error(1)
}

func checkMetaAll(vars []VariableType, mask MetaType) bool {
	for _, v := range vars {
		if v.Meta()&mask == 0 {
			return false
		}
	}
	return true
}

func TestVariables_InitFileScanVariables(t *testing.T) {
	var vr Variables
	vr.InitFileVariables(AllVars)
	require.True(t, checkMetaAll(vr.Variables(), MetaFile))
}

func TestVariables_InitProcessScanVariables(t *testing.T) {
	var vr Variables
	vr.InitProcessVariables(AllVars)
	require.True(t, checkMetaAll(vr.Variables(), MetaProcess))
}

func TestVariables_InitAll(t *testing.T) {
	var vr Variables
	vr.InitProcessVariables(AllVars)
	vr.InitFileVariables(AllVars)
	require.True(t, checkMetaAll(vr.Variables(), MetaProcess))
	require.True(t, checkMetaAll(vr.Variables(), MetaFile))
}

func TestVariables_DefineCompilerVariables(t *testing.T) {
	type args struct {
		compiler *variableDefinerMock
	}
	tests := []struct {
		name    string
		vars    []VariableType
		initer  func(*Variables, []VariableType)
		args    args
		wantErr bool
	}{
		{
			vars:   []VariableType{},
			initer: (*Variables).InitFileVariables,
			args: args{
				compiler: new(variableDefinerMock),
			},
		},
		{
			vars:   []VariableType{},
			initer: (*Variables).InitProcessVariables,
			args: args{
				compiler: new(variableDefinerMock),
			},
		},
		{
			vars:   []VariableType{0},
			initer: (*Variables).InitFileVariables,
			args: args{
				compiler: new(variableDefinerMock),
			},
		},
		{
			vars:   []VariableType{0},
			initer: (*Variables).InitProcessVariables,
			args: args{
				compiler: new(variableDefinerMock),
			},
		},
		{
			vars:   []VariableType{VarFilePath},
			initer: (*Variables).InitFileVariables,
			args: args{
				compiler: func() *variableDefinerMock {
					m := new(variableDefinerMock)
					m.On("DefineVariable", VarFilePath.String(), defaultVarValue(VarFilePath.Meta())).Return(nil)
					return m
				}(),
			},
		},
		{
			vars:   []VariableType{VarFilePath, AllVarsOnlyProcs[0]},
			initer: (*Variables).InitFileVariables,
			args: args{
				compiler: func() *variableDefinerMock {
					m := new(variableDefinerMock)
					m.On("DefineVariable", VarFilePath.String(), defaultVarValue(VarFilePath.Meta())).Return(nil)
					return m
				}(),
			},
		},
		{
			vars:   []VariableType{VarProcessId},
			initer: (*Variables).InitProcessVariables,
			args: args{
				compiler: func() *variableDefinerMock {
					m := new(variableDefinerMock)
					m.On("DefineVariable", VarProcessId.String(), defaultVarValue(VarProcessId.Meta())).Return(nil)
					return m
				}(),
			},
		},
		{
			vars:   []VariableType{VarOs},
			initer: (*Variables).InitProcessVariables,
			args: args{
				compiler: func() *variableDefinerMock {
					m := new(variableDefinerMock)
					m.On("DefineVariable", VarOs.String(), defaultVarValue(VarOs.Meta())).Return(nil)
					return m
				}(),
			},
		},
		{
			vars:   []VariableType{VarOsLinux},
			initer: (*Variables).InitProcessVariables,
			args: args{
				compiler: func() *variableDefinerMock {
					m := new(variableDefinerMock)
					m.On("DefineVariable", VarOsLinux.String(), defaultVarValue(VarOsLinux.Meta())).Return(nil)
					return m
				}(),
			},
		},
		{
			vars:   []VariableType{VarFileName, VarFileExtension},
			initer: (*Variables).InitFileVariables,
			args: args{
				compiler: func() *variableDefinerMock {
					m := new(variableDefinerMock)
					m.On("DefineVariable", VarFileName.String(), defaultVarValue(VarFileName.Meta())).Return(nil)
					m.On("DefineVariable", VarFileExtension.String(), defaultVarValue(VarFileExtension.Meta())).Return(nil)
					return m
				}(),
			},
		},
		{
			vars:   []VariableType{VarFileName},
			initer: (*Variables).InitFileVariables,
			args: args{
				compiler: func() *variableDefinerMock {
					m := new(variableDefinerMock)
					m.On("DefineVariable", VarFileName.String(), defaultVarValue(VarFileName.Meta())).
						Return(errors.New("test error"))
					return m
				}(),
			},
			wantErr: true,
		},
		{
			vars:   []VariableType{VarProcessId},
			initer: (*Variables).InitProcessVariables,
			args: args{
				compiler: func() *variableDefinerMock {
					m := new(variableDefinerMock)
					m.On("DefineVariable", VarProcessId.String(), defaultVarValue(VarProcessId.Meta())).
						Return(errors.New("test error"))
					return m
				}(),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var vr Variables
			tt.initer(&vr, tt.vars)
			if err := vr.DefineCompilerVariables(tt.args.compiler); (err != nil) != tt.wantErr {
				t.Errorf("Variables.DefineCompilerVariables() error = %v, wantErr %v", err, tt.wantErr)
			}
			tt.args.compiler.AssertExpectations(t)
		})
	}
}

func TestVariables_DefineScannerVariables(t *testing.T) {
	type args struct {
		sCtx    *scanContextMock
		scanner *variableDefinerMock
	}
	tests := []struct {
		name    string
		vars    []VariableType
		initer  func(*Variables, []VariableType)
		args    args
		wantErr bool
	}{
		{
			vars:   []VariableType{},
			initer: (*Variables).InitFileVariables,
			args: args{
				sCtx:    new(scanContextMock),
				scanner: new(variableDefinerMock),
			},
		},
		{
			vars:   []VariableType{},
			initer: (*Variables).InitProcessVariables,
			args: args{
				sCtx:    new(scanContextMock),
				scanner: new(variableDefinerMock),
			},
		},
		{
			vars:   []VariableType{VarFilePath},
			initer: (*Variables).InitFileVariables,
			args: args{
				sCtx: func() *scanContextMock {
					m := new(scanContextMock)
					if runtime.GOOS != "windows" {
						m.On("FilePath").Return("/tmp/a/b/c").Times(1)
					} else {
						m.On("FilePath").Return(`c:\tmp\a\b\c`).Times(1)
					}
					return m
				}(),
				scanner: func() *variableDefinerMock {
					m := new(variableDefinerMock)
					if runtime.GOOS != "windows" {
						m.On("DefineVariable", VarFilePath.String(), "/tmp/a/b/c").Return(nil)
					} else {
						m.On("DefineVariable", VarFilePath.String(), `c:\tmp\a\b\c`).Return(nil)
					}
					return m
				}(),
			},
		},
		{
			vars:   []VariableType{VarFilePath},
			initer: (*Variables).InitFileVariables,
			args: args{
				sCtx: func() *scanContextMock {
					m := new(scanContextMock)
					m.On("FilePath").Return("").Times(1)
					return m
				}(),
				scanner: func() *variableDefinerMock {
					m := new(variableDefinerMock)
					m.On("DefineVariable", VarFilePath.String(), defaultVarValue(VarFilePath.Meta())).Return(nil)
					return m
				}(),
			},
		},
		{
			vars:   []VariableType{VarFilePath, VarFileName},
			initer: (*Variables).InitFileVariables,
			args: args{
				sCtx: func() *scanContextMock {
					m := new(scanContextMock)
					if runtime.GOOS != "windows" {
						m.On("FilePath").Return("a/b/c").Times(2)
					} else {
						m.On("FilePath").Return(`a\b\c`).Times(2)
					}
					return m
				}(),
				scanner: func() *variableDefinerMock {
					m := new(variableDefinerMock)
					if runtime.GOOS != "windows" {
						m.On("DefineVariable", VarFilePath.String(), "a/b/c").Return(nil)
					} else {
						m.On("DefineVariable", VarFilePath.String(), `a\b\c`).Return(nil)
					}
					m.On("DefineVariable", VarFileName.String(), "c").Return(nil)
					return m
				}(),
			},
		},
		{
			vars:   []VariableType{VarProcessId, VarFileName},
			initer: (*Variables).InitProcessVariables,
			args: args{
				sCtx: func() *scanContextMock {
					m := new(scanContextMock)
					m.On("Pid").Return(1).Times(1)
					m.On("FilePath").Return("a/b/c").Times(1)
					return m
				}(),
				scanner: func() *variableDefinerMock {
					m := new(variableDefinerMock)
					m.On("DefineVariable", VarProcessId.String(), int64(1)).Return(nil)
					m.On("DefineVariable", VarFileName.String(), "c").Return(nil)
					return m
				}(),
			},
		},
		{
			vars:   []VariableType{VarProcessName},
			initer: (*Variables).InitProcessVariables,
			args: args{
				sCtx: func() *scanContextMock {
					m := new(scanContextMock)
					m.On("Context").Return(context.Background()).Times(1)
					pi := new(processInfoMock)
					pi.On("NameWithContext", context.Background()).Return("", nil).Times(1)
					m.On("ProcessInfo").Return(pi).Times(1)
					return m
				}(),
				scanner: func() *variableDefinerMock {
					m := new(variableDefinerMock)
					m.On("DefineVariable", VarProcessName.String(), defaultVarValue(VarProcessName.Meta())).Return(nil)
					return m
				}(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var vr Variables
			tt.initer(&vr, tt.vars)
			if err := vr.DefineScannerVariables(tt.args.sCtx, tt.args.scanner); (err != nil) != tt.wantErr {
				t.Errorf("Variables.DefineScannerVariables() error = %v, wantErr %v", err, tt.wantErr)
			}
			tt.args.scanner.AssertExpectations(t)
			tt.args.sCtx.AssertExpectations(t)

		})
	}

}

func TestVariables_DefineScannerVariables_valueError(t *testing.T) {
	orig := Valuers
	t.Cleanup(func() {
		Valuers = orig
	})

	Valuers[VarFilePath] = ValueFunc(func(_ ScanContext) (interface{}, error) {
		return nil, errors.New("test error")
	})

	sCtx := new(scanContextMock)
	errValTest := errors.New("test value error")
	sCtx.On("HandleValueError").Return(errValTest).Times(1)

	scanner := new(variableDefinerMock)
	scanner.On("DefineVariable", VarFilePath.String(), defaultVarValue(VarFilePath.Meta())).Return(nil).Times(1)

	var vr Variables
	vr.InitFileVariables([]VariableType{VarFilePath})

	err := vr.DefineScannerVariables(sCtx, scanner)
	require.Error(t, err)
	require.Same(t, errValTest, err)
}

func defaultVarValue(meta MetaType) (defVal interface{}) {

	if meta&MetaString != 0 {
		defVal = ""
	} else if meta&MetaInt != 0 {
		defVal = int64(0)
	} else if meta&MetaBool != 0 {
		defVal = false
	} else if meta&MetaFloat != 0 {
		defVal = float64(0)
	} else {
		panic(fmt.Errorf("unknown meta: %v", meta))
	}
	return
}

func TestVariables_Copy(t *testing.T) {
	vr1 := new(Variables)
	vr1.InitFileVariables(AllVars)

	got := vr1.Copy()
	if !reflect.DeepEqual(got, vr1) {
		t.Errorf("Variables.Copy() = %v, want %v", got, vr1)
	}
}
