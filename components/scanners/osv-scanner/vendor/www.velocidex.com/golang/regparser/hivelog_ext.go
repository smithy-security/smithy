package regparser

import (
	"fmt"
	"io"
)

type DirtyPage struct {
	Reader     io.ReaderAt
	DataOffset int64
	PageOffset uint32
	PageSize   uint32
}

func (self DirtyPage) Data() ([]byte, error) {
	buf := make([]byte, self.PageSize)

	if n, err := self.Reader.ReadAt(buf, self.DataOffset); err != nil {
		return nil, err
	} else if n != int(self.PageSize) {
		return nil, fmt.Errorf("reader returned unexpected size (got %#x, want %#x)", n, self.PageSize)
	}

	return buf, nil
}

func (self HIVE_LOG_ENTRY) GetDirtyPages() []*DirtyPage {
	x := &HIVE_DIRTY_PAGE_REF{}

	pages := make([]*DirtyPage, 0, self.DirtyPagesCount())

	page_data_offset := self.Offset + self.Profile.Off_HIVE_LOG_ENTRY_DirtyPageRefs + int64(self.DirtyPagesCount())*int64(x.Size())

	for _, pageRef := range self.DirtyPageRefs() {
		page := &DirtyPage{
			Reader:     self.Reader,
			DataOffset: page_data_offset,
			PageOffset: pageRef.PageOffset(),
			PageSize:   pageRef.PageSize(),
		}
		page_data_offset += int64(pageRef.PageSize())

		pages = append(pages, page)
	}

	return pages
}
