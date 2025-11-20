package parser

import "io"

type OffsetReader struct {
	Offset int64
	Reader io.ReaderAt
}

func (self *OffsetReader) ReadAt(buf []byte, offset int64) (int, error) {
	return self.Reader.ReadAt(buf, offset+self.Offset)
}
