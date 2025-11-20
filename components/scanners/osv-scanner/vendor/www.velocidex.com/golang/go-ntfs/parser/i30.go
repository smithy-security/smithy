package parser

import (
	"fmt"
	"io"
)

func new_file_info(record *INDEX_RECORD_ENTRY) *FileInfo {
	filename := record.File()
	return &FileInfo{
		MFTId:         fmt.Sprintf("%d", record.MftReference()),
		Mtime:         filename.Mft_modified().Time,
		Atime:         filename.File_accessed().Time,
		Ctime:         filename.Created().Time,
		Btime:         filename.File_modified().Time,
		Size:          int64(filename.FilenameSize()),
		AllocatedSize: int64(filename.Allocated_size()),
		Name:          filename.Name(),
		NameType:      filename.NameType().Name,
	}
}

func ExtractI30ListFromStream(
	ntfs *NTFSContext,
	reader io.ReaderAt,
	stream_size int64) []*FileInfo {
	result := []*FileInfo{}

	add_record := func(slack bool, record *INDEX_RECORD_ENTRY) {
		if !record.IsValid() {
			return
		}

		slack_offset := int64(0)
		if slack {
			slack_offset = record.Offset
		}
		fi := new_file_info(record)
		fi.IsSlack = slack
		fi.SlackOffset = slack_offset
		result = append(result, fi)
	}

	for i := int64(0); i < stream_size; i += 0x1000 {
		index_root, err := DecodeSTANDARD_INDEX_HEADER(
			ntfs, reader, i, 0x1000)
		if err != nil {
			continue
		}

		node := index_root.Node()
		for _, record := range node.GetRecords(ntfs) {
			add_record(false, record)
		}

		for _, record := range node.ScanSlack(ntfs) {
			add_record(true, record)
		}
	}

	return result
}

func ExtractI30List(ntfs *NTFSContext, mft_entry *MFT_ENTRY) []*FileInfo {
	results := []*FileInfo{}
	for _, attr := range mft_entry.EnumerateAttributes(ntfs) {
		switch attr.Type().Value {

		case ATTR_TYPE_INDEX_ROOT:
			index_root := ntfs.Profile.INDEX_ROOT(
				attr.Data(ntfs), 0)
			for _, record := range index_root.Node().GetRecords(ntfs) {
				results = append(results, new_file_info(record))
			}

		case ATTR_TYPE_INDEX_ALLOCATION:
			attr_reader := attr.Data(ntfs)
			results = append(results,
				ExtractI30ListFromStream(ntfs,
					attr_reader,
					attr.DataSize())...)
		}
	}

	return results
}

const (
	earliest_valid_time = 1000000000 // Sun Sep  9 11:46:40 2001
	latest_valid_time   = 2000000000 // Wed May 18 13:33:20 2033
)

func (self *INDEX_RECORD_ENTRY) IsValid() bool {
	test_filename := self.File()

	x := test_filename.File_modified().Unix()
	if x < earliest_valid_time || x > latest_valid_time {
		return false
	}

	x = test_filename.File_accessed().Unix()
	if x < earliest_valid_time || x > latest_valid_time {
		return false
	}

	x = test_filename.Mft_modified().Unix()
	if x < earliest_valid_time || x > latest_valid_time {
		return false
	}

	x = test_filename.Created().Unix()
	if x < earliest_valid_time || x > latest_valid_time {
		return false
	}

	return true
}

func (self *INDEX_NODE_HEADER) ScanSlack(ntfs *NTFSContext) []*INDEX_RECORD_ENTRY {
	result := []*INDEX_RECORD_ENTRY{}

	// start at the last record and carve until the end of the
	// allocation.
	start := int32(self.Offset_to_end_index_entry())
	end := self.SizeOfEntriesAlloc() - 0x52
	for off := start; off < end; off++ {
		test_struct := self.Profile.INDEX_RECORD_ENTRY(self.Reader, int64(off))
		if test_struct.IsValid() {
			result = append(result, test_struct)
		}
	}

	return result
}
