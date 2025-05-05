package gora

import (
	"errors"
	"sync"

	"golang.org/x/sys/windows"
)

// WorkingSetHandler is a helper to empty the working set of a Windows process
// after Yara Process scan. It should be initialized with NewWorkingSetHandler
// before scanning a process, and then call EmptyWorkingSet() method after a
// scan completes successfully, without errors.
//
// The caller is responsible for closing the handle with Close() after
// EmptyWorkingSet() has been called.
type WorkingSetHandler struct {
	hProc     windows.Handle
	emptyOnce sync.Once
	closeOnce sync.Once
}

// NewWorkingSetHandler creates a new WorkingSetHandler. If the given pid cannot
// be opened with the required access, an error will be returned.
// The caller is responsible for closing the handle with Close() after calling
// EmptyWorkingSet().
func NewWorkingSetHandler(pid uint32) (*WorkingSetHandler, error) {
	const desiredAccess = windows.PROCESS_SET_QUOTA | windows.PROCESS_QUERY_INFORMATION
	const inheritHandle = false

	hProc, err := windows.OpenProcess(desiredAccess, inheritHandle, pid)
	if err != nil {
		return nil, err
	}

	return &WorkingSetHandler{
		hProc: hProc,
	}, nil
}

// Close closes the handle to the process. Subsequent calls to this method will
// do nothing. Other methods must not be called after this method has been
// called.
func (w *WorkingSetHandler) Close() (err error) {
	if !w.isValidHandle() {
		return errors.New("invalid process handle")
	}

	w.closeOnce.Do(func() {
		err = windows.CloseHandle(w.hProc)
	})
	return
}

// EmptyWorkingSet empties the working set of the process.
// Subsequent calls to this method will do nothing.
func (w *WorkingSetHandler) EmptyWorkingSet() (err error) {
	if !w.isValidHandle() {
		return errors.New("invalid process handle")
	}

	w.emptyOnce.Do(func() {
		// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-setprocessworkingsetsizeex
		//
		// The working set of the specified process can be emptied by specifying
		// the value (SIZE_T)–1 for both the minimum and maximum working set
		// sizes. This removes as many pages as possible from the working set.
		//
		err = windows.SetProcessWorkingSetSizeEx(
			w.hProc,
			^uintptr(0), // (SIZE_T)–1
			^uintptr(0), // (SIZE_T)–1
			0,
		)
	})
	return
}

func (w *WorkingSetHandler) isValidHandle() bool {
	return w.hProc != windows.InvalidHandle && w.hProc != 0
}
