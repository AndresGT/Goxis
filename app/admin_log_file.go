package goxis

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const (
	defaultAdminLogPath      = "logs/goxis-admin.log"
	defaultAdminLogFileBytes = int64(10 << 20)
	defaultAdminLogFiles     = 5
	maxAdminLogFileBytes     = int64(1 << 30)
)

type adminLogFile struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	maxFiles int
	file     *os.File
	size     int64
}

func openAdminLogFile(path string, maxBytes int64, maxFiles int) (*adminLogFile, []string, error) {
	if path == "" {
		path = defaultAdminLogPath
	}
	if maxBytes <= 0 {
		maxBytes = defaultAdminLogFileBytes
	}
	if maxBytes > maxAdminLogFileBytes {
		maxBytes = maxAdminLogFileBytes
	}
	if maxFiles < 1 {
		maxFiles = defaultAdminLogFiles
	}
	if maxFiles > 100 {
		maxFiles = 100
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, nil, err
	}

	recent, err := readRecentAdminLogFiles(path, maxFiles)
	if err != nil {
		return nil, nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, nil, err
	}
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	return &adminLogFile{path: path, maxBytes: maxBytes, maxFiles: maxFiles, file: file, size: info.Size()}, recent, nil
}

func readRecentAdminLogFiles(path string, maxFiles int) ([]string, error) {
	paths := make([]string, 0, maxFiles+1)
	for index := maxFiles; index >= 1; index-- {
		paths = append(paths, path+"."+itoa(index))
	}
	paths = append(paths, path)
	var recent []string
	for _, name := range paths {
		file, err := os.Open(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 4096), 1<<20)
		for scanner.Scan() {
			recent = append(recent, scanner.Text())
		}
		scanErr := scanner.Err()
		closeErr := file.Close()
		if scanErr != nil {
			return nil, scanErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
	}
	return recent, nil
}

func (w *adminLogFile) Write(data []byte) (int, error) {
	if w == nil {
		return len(data), nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return 0, os.ErrClosed
	}
	if w.size > 0 && w.size+int64(len(data)) > w.maxBytes {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := w.file.Write(data)
	w.size += int64(n)
	return n, err
}

func (w *adminLogFile) rotate() error {
	if err := w.file.Close(); err != nil {
		return err
	}
	w.file = nil
	oldest := w.path + "." + itoa(w.maxFiles)
	if err := os.Remove(oldest); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for i := w.maxFiles - 1; i >= 1; i-- {
		source, target := w.path+"."+itoa(i), w.path+"."+itoa(i+1)
		if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.Rename(source, target); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.Rename(w.path, w.path+".1"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(w.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return err
	}
	w.file, w.size = file, 0
	return nil
}

func (w *adminLogFile) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	if err := w.file.Sync(); err != nil {
		_ = w.file.Close()
		w.file = nil
		return err
	}
	err := w.file.Close()
	w.file = nil
	return err
}

var _ io.WriteCloser = (*adminLogFile)(nil)

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var buffer [20]byte
	i := len(buffer)
	for value > 0 {
		i--
		buffer[i] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[i:])
}
