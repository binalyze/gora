package variables

import (
	"context"
	"io/fs"
)

// ScanContextImpl implements the ScanContext interface. It is a simple implementation to set the required values to be
// used as ScanContext interface.
type ScanContextImpl struct {
	ctx          context.Context
	finfo        fs.FileInfo
	fpath        string
	pid          int
	proc         ProcessInfo
	inProcess    bool
	inFileSystem bool
	valErrFn     func(VariableDefiner, VariableType, error) error
}

var _ ScanContext = (*ScanContextImpl)(nil)

// Reset resets all the fields to be able to reuse the same ScanContextImpl instance.
func (sc *ScanContextImpl) Reset() {
	sc.ctx = nil
	sc.finfo = nil
	sc.fpath = ""
	sc.pid = 0
	sc.proc = nil
	sc.valErrFn = nil
	sc.inProcess = false
	sc.inFileSystem = false
}

// Context is to implement the ScanContext interface. It returns context.Background() if underlying context is missing.
func (sc *ScanContextImpl) Context() context.Context {
	if sc.ctx == nil {
		return context.Background()
	}
	return sc.ctx
}

// SetContext sets the underlying context to be returned from Context method.
func (sc *ScanContextImpl) SetContext(ctx context.Context) {
	sc.ctx = ctx
}

// FileInfo is to implement the ScanContext interface.
func (sc *ScanContextImpl) FileInfo() fs.FileInfo {
	return sc.finfo
}

// SetFileInfo sets the underlying file info to be returned from FileInfo method.
func (sc *ScanContextImpl) SetFileInfo(f fs.FileInfo) {
	sc.finfo = f
}

// FilePath is to implement the ScanContext interface.
func (sc *ScanContextImpl) FilePath() string {
	return sc.fpath
}

// SetFilePath sets the underlying file path to be returned from FilePath method.
func (sc *ScanContextImpl) SetFilePath(p string) {
	sc.fpath = p
}

// SetInFileSystem sets file system context flag
func (sc *ScanContextImpl) SetInFileSystem(v bool) {
	sc.inFileSystem = v
}

// InFileSystem is to implement the ScanContext interface.
func (sc *ScanContextImpl) InFileSystem() bool {
	return sc.inFileSystem
}

// SetInProcess is to implement the ScanContext interface.
func (sc *ScanContextImpl) SetInProcess(v bool) {
	sc.inProcess = v
}

// InProcess is to implement the ScanContext interface.
func (sc *ScanContextImpl) InProcess() bool {
	return sc.inProcess
}

// HandleValueError is to implement the ScanContext interface. It calls underlying value error handler if exists,
// otherwise it returns the provided error to the caller.
func (sc *ScanContextImpl) HandleValueError(d VariableDefiner, v VariableType, err error) error {
	if sc.valErrFn == nil {
		return err
	}
	return sc.valErrFn(d, v, err)
}

// SetHandleValueError sets the underlying value error handler.
func (sc *ScanContextImpl) SetHandleValueError(fn func(VariableDefiner, VariableType, error) error) {
	sc.valErrFn = fn
}

// Pid is to implement the ScanContext interface.
func (sc *ScanContextImpl) Pid() int {
	return sc.pid
}

// SetPid sets the underlying process id to be returned from Pid method.
func (sc *ScanContextImpl) SetPid(v int) {
	sc.pid = v
}

// ProcessInfo is to implement the ScanContext interface.
func (sc *ScanContextImpl) ProcessInfo() ProcessInfo {
	return sc.proc
}

// SetProcess sets the underlying process to be returned from Process method.
func (sc *ScanContextImpl) SetProcessInfo(p ProcessInfo) {
	sc.proc = p
}
