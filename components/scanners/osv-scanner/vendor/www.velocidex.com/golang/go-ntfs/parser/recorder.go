package parser

import (
	"fmt"
	"io"
	"os"
)

type Recorder struct {
	path string

	// Delegate reader
	reader io.ReaderAt
}

func (self *Recorder) ReadAt(buf []byte, offset int64) (int, error) {
	// Check if the read comes from the cache directory.
	full_path := fmt.Sprintf("%s/%#08x.bin", self.path, offset)
	fd, err := os.Open(full_path)
	if err != nil {
		// Cache file does not exist - pass the read to the
		// delegate and cache it for next time.
		n, err := self.reader.ReadAt(buf, offset)
		if err == nil || err == io.EOF {
			fd, err := os.OpenFile(full_path,
				os.O_RDWR|os.O_CREATE, 0660)
			if err == nil {
				fd.Write(buf[:n])
			}
		}
		return n, err
	}
	defer fd.Close()

	return fd.ReadAt(buf, 0)
}

func NewRecorder(path string, reader io.ReaderAt) *Recorder {
	return &Recorder{path: path, reader: reader}
}
