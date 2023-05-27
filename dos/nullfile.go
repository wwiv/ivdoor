package dos

import (
	"os"
	"time"
)

type NullFile struct {
}

// New creates new mock NullFile, which can be used as os.File.
func NewNullFile() *NullFile {
	return &NullFile{}
}

func (m *NullFile) Close() error {
	return nil
}

func (m *NullFile) Read(p []byte) (n int, err error) {
	return 0, nil
}

func (m *NullFile) Seek(offset int64, whence int) (int64, error) {
	return 0, nil
}

func (m *NullFile) Stat() (os.FileInfo, error) {
	return fileInfo{0}, nil
}

func (m *NullFile) ReadAt(p []byte, off int64) (n int, err error) {
	return 0, nil
}

type fileInfo struct {
	size int64
}

func (m fileInfo) Name() string {
	return ""
}

func (m fileInfo) Size() int64 {
	return 0
}

func (m fileInfo) Mode() os.FileMode {
	return os.FileMode(0)
}

func (m fileInfo) ModTime() time.Time {
	return time.Time{}
}

func (m fileInfo) IsDir() bool {
	return false
}

func (m fileInfo) Sys() interface{} {
	return nil
}

func (m *NullFile) Write(p []byte) (n int, err error) {
	return 0, nil
}

func (m *NullFile) Truncate(size int64) error {
	return nil
}
