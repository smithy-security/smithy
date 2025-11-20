package parser

import (
	"fmt"
	"io"
	"time"
)

func filetimeToUnixtime(ft uint64) uint64 {
	return (ft - 11644473600000*10000) * 100
}

// A FileTime object is a timestamp in windows filetime format.
type WinFileTime struct {
	time.Time
}

func (self *WinFileTime) GoString() string {
	return fmt.Sprintf("%v", self)
}

func (self *WinFileTime) DebugString() string {
	return fmt.Sprintf("%v", self)
}

func (self *NTFSProfile) WinFileTime(reader io.ReaderAt, offset int64) *WinFileTime {
	filetime := ParseUint64(reader, offset)
	return &WinFileTime{time.Unix(0, int64(filetimeToUnixtime(filetime))).UTC()}
}
