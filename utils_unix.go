//go:build !windows

package gora

// WorkingSetHandler is a helper for Windows, and it is a no-op for other
// platforms.
type WorkingSetHandler struct{}

// NewWorkingSetHandler creates a new no-op WorkingSetHandler.
func NewWorkingSetHandler(pid uint32) (*WorkingSetHandler, error) {
	return &WorkingSetHandler{}, nil
}

// EmptyWorkingSet does nothing on non-Windows platforms.
func (w *WorkingSetHandler) EmptyWorkingSet() error {
	return nil
}

// Close does nothing on non-Windows platforms.
func (w *WorkingSetHandler) Close() error {
	return nil
}
