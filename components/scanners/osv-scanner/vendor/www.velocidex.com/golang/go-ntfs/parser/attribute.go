package parser

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

type Range struct {
	// In bytes
	Offset, Length int64
	IsSparse       bool
}

type RangeReaderAt interface {
	io.ReaderAt

	Ranges() []Range
}

type LimitedReader struct {
	RangeReaderAt
	N int64
}

func (self LimitedReader) ReadAt(buff []byte, off int64) (int, error) {
	n, err := self.RangeReaderAt.ReadAt(buff, off)

	if off+int64(n) > self.N {
		n = int(self.N - off)
	}

	return n, err
}

// Returns the data stream in this attribute.  NOTE: A normal file may
// consist of multiple separate data streams (VCNs). To read a file
// you will need to call OpenStream() below.
func (self *NTFS_ATTRIBUTE) Data(ntfs *NTFSContext) io.ReaderAt {
	if self.Resident().Name == "RESIDENT" {
		buf := make([]byte, CapUint32(self.Content_size(), 16*1024))
		n, _ := self.Reader.ReadAt(
			buf,
			self.Offset+int64(self.Content_offset()))
		buf = buf[:n]

		return bytes.NewReader(buf)
	}

	return &RangeReader{
		runs: joinAllVCNs(ntfs, []*NTFS_ATTRIBUTE{self}),
	}
}

func (self *NTFS_ATTRIBUTE) Name() string {
	length := int64(self.name_length()) * 2
	result := ParseUTF16String(self.Reader,
		self.Offset+int64(self.name_offset()),
		CapInt64(length, MAX_ATTR_NAME_LENGTH))
	return result
}

func (self *NTFS_ATTRIBUTE) IsResident() bool {
	return self.Resident().Value == 0
}

func (self *NTFS_ATTRIBUTE) DataSize() int64 {
	if self.Resident().Name == "RESIDENT" {
		return int64(self.Content_size())
	}

	return int64(self.Actual_size())
}

func (self *NTFS_ATTRIBUTE) PrintStats(ntfs *NTFSContext) string {
	result := []string{}

	if self.Resident().Name == "RESIDENT" {
		obj := self.Profile.NTFS_RESIDENT_ATTRIBUTE(self.Reader,
			self.Offset)
		result = append(result, obj.DebugString())

	} else {
		result = append(result, self.DebugString())
	}

	length := self.Actual_size()
	b := make([]byte, CapUint64(length, 100))
	reader := self.Data(ntfs)
	n, _ := reader.ReadAt(b, 0)
	b = b[:n]

	name := self.Name()
	if name != "" {
		result = append(result, "Name: "+name)
	}

	if self.Resident().Name != "RESIDENT" {
		result = append(result, fmt.Sprintf(
			"Runlist: %v", self.RunList()))
	}

	result = append(result, fmt.Sprintf("Data: \n%s", hex.Dump(b)))
	return strings.Join(result, "\n")
}

type Run struct {
	Offset            int64
	RelativeUrnOffset int64
	Length            int64
}

func (self *NTFS_ATTRIBUTE) RunList() []*Run {
	var disk_offset int64

	result := []*Run{}

	attr_length := self.Length()
	runlist_offset := self.Offset + int64(self.Runlist_offset())

	/* Make sure we are instantiated on top of a fixed up MFT entry.

	is_fixed := IsFixed(self.Reader, runlist_offset)
	if !is_fixed {
		DlvBreak()
	}
	fmt.Printf("RunList on fixed %v\n", IsFixed(self.Reader, runlist_offset))

	*/

	// Read the entire attribute into memory. This makes it easier
	// to parse the runlist.
	buffer := make([]byte, CapUint32(attr_length, MAX_RUNLIST_SIZE))
	n, _ := self.Reader.ReadAt(buffer, runlist_offset)
	buffer = buffer[:n]

	length_buffer := make([]byte, 8)
	offset_buffer := make([]byte, 8)

	for offset := 0; offset < len(buffer); {
		// Consume the first byte off the stream.
		idx := buffer[offset]
		if idx == 0 {
			break
		}

		length_size := int(idx & 0xF)
		run_offset_size := int(idx >> 4)
		offset += 1

		// Pad out to 8 bytes
		for i := 0; i < 8; i++ {
			// This should not happen but we protect from overflow.
			value := byte(0)
			if offset < len(buffer) {
				value = buffer[offset]
			}

			if i < length_size {
				length_buffer[i] = value
				offset++
			} else {
				length_buffer[i] = 0
			}
		}

		// Sign extend if the last byte is larger than 0x80.
		var sign byte = 0x00
		for i := 0; i < 8; i++ {
			// This should not happen but we protect from overflow.
			value := byte(0)
			if offset < len(buffer) {
				value = buffer[offset]
			}

			if i == run_offset_size-1 &&
				buffer[offset]&0x80 != 0 {
				sign = 0xFF
			}

			if i < run_offset_size {
				offset_buffer[i] = value
				offset++
			} else {
				offset_buffer[i] = sign
			}
		}

		relative_run_offset := int64(
			binary.LittleEndian.Uint64(offset_buffer))

		run_length := int64(binary.LittleEndian.Uint64(
			length_buffer))
		disk_offset += relative_run_offset
		result = append(result, &Run{
			Offset:            disk_offset,
			RelativeUrnOffset: relative_run_offset,
			Length:            run_length,
		})
	}

	return result
}

// A reader mapping from file space to target space. A ReadAt in file
// space will be mapped to a ReadAt in target space.
type MappedReader struct {
	FileOffset       int64 // Address in the file this range begins
	TargetOffset     int64 // Address in the target reader the range is mapped to.
	Length           int64 // Length of mapping.
	ClusterSize      int64
	CompressedLength int64 // For compressed readers, we need to decompress on read.
	IsSparse         bool
	Reader           io.ReaderAt
}

func (self *MappedReader) IsFixed(offset int64) bool {
	return IsFixed(self.Reader, offset-
		self.FileOffset*self.ClusterSize+
		self.TargetOffset*self.ClusterSize)
}

func (self *MappedReader) VtoP(offset int64) int64 {
	return VtoP(self.Reader, offset-
		self.FileOffset*self.ClusterSize+
		self.TargetOffset*self.ClusterSize)
}

func (self *MappedReader) ReadAt(buff []byte, off int64) (int, error) {
	// Figure out where to read from in target space.
	buff_offset := off - self.FileOffset

	// How much is actually available to read
	to_read := self.FileOffset + self.Length - off
	if to_read > int64(len(buff)) {
		to_read = int64(len(buff))
	}

	if to_read < 0 {
		return 0, io.EOF
	}

	return self.Reader.ReadAt(buff[:to_read], buff_offset)
}

func (self *MappedReader) DebugString() string {
	return fmt.Sprintf("Mapping %v -> %v (length %v) with %T\n%v",
		self.FileOffset*self.ClusterSize,
		self.Length*self.ClusterSize+self.FileOffset*self.ClusterSize,
		self.Length*self.ClusterSize,
		self.Reader, _DebugString(self.Reader, "  "))
}

// Trim the delegate ranges to our own mapping length.
func (self *MappedReader) Ranges() []Range {
	result := []Range{}

	offset := self.FileOffset * self.ClusterSize
	end_offset := offset + self.Length*self.ClusterSize

	for _, run := range self._Ranges() {
		if run.Offset > offset {
			result = append(result, Range{
				Offset:   offset,
				Length:   run.Offset - offset,
				IsSparse: true,
			})
			offset = run.Offset
		}

		if run.Offset+run.Length > end_offset {
			result = append(result, Range{
				Offset:   offset,
				Length:   end_offset - run.Offset,
				IsSparse: run.IsSparse,
			})
			return result
		}

		result = append(result, run)
		offset += run.Length
	}

	if end_offset > offset {
		// Pad to the end of our mapped range.
		result = append(result, Range{
			Offset:   offset,
			Length:   end_offset - offset,
			IsSparse: true,
		})
	}

	return result
}

func (self *MappedReader) _Ranges() []Range {
	// If the delegate can tell us more about its ranges then pass
	// it on otherwise we consider the entire run a single range.
	delegate, ok := self.Reader.(RangeReaderAt)
	if ok {
		result := []Range{}
		for _, rng := range delegate.Ranges() {
			rng.Offset += self.FileOffset * self.ClusterSize
			result = append(result, rng)
		}
		return result
	}

	// Ranges are given in bytes.
	return []Range{Range{
		Offset:   self.FileOffset * self.ClusterSize,
		Length:   self.Length * self.ClusterSize,
		IsSparse: self.IsSparse,
	}}
}

func (self *MappedReader) Decompress(reader io.ReaderAt, cluster_size int64) ([]byte, error) {
	DebugPrint("Decompress %v\n", self)
	compressed := make([]byte,
		CapInt64(self.CompressedLength*cluster_size, MAX_DECOMPRESSED_FILE))
	n, err := reader.ReadAt(compressed, self.TargetOffset*cluster_size)
	if err != nil && err != io.EOF {
		return compressed, err
	}
	compressed = compressed[:n]

	debugLZNT1Decompress("Reading compression unit at cluster %d length %d\n",
		self.TargetOffset, self.CompressedLength)
	decompressed, err := LZNT1Decompress(compressed)
	return decompressed, err
}

// An io.ReaderAt which works off a sequence of runs. Each run is a
// mapping between filespace to another reader at a specific offset in
// the file address space.
type RangeReader struct {
	runs []*MappedReader
}

// Combine the ranges from all the Mapped readers.
func (self *RangeReader) Ranges() []Range {
	result := make([]Range, 0, len(self.runs))
	for _, run := range self.runs {
		if run.Length > 0 {
			result = append(result, run.Ranges()...)
		}
	}
	return result
}

func (self *RangeReader) DebugString() string {
	result := fmt.Sprintf("RangeReader with %v runs:\n", len(self.runs))
	for idx, run := range self.runs {
		result += fmt.Sprintf(
			"Run %v (%T):\n%v\n", idx, run,
			_DebugString(run, "  "))
	}
	return result
}

func NewUncompressedRangeReader(
	runs []*Run,
	cluster_size int64,
	disk_reader io.ReaderAt,
	is_sparse bool) *RangeReader {

	result := &RangeReader{}
	var file_offset int64

	for idx := 0; idx < len(runs); idx++ {
		run := runs[idx]

		// Ignore this run since it has no length.
		if run.Length == 0 {
			continue
		}

		reader_run := &MappedReader{
			FileOffset:   file_offset,
			TargetOffset: run.Offset, // Offset of run on disk

			// Take up the entire compression unit
			Length:      run.Length,
			ClusterSize: cluster_size,
			Reader:      disk_reader,
		}

		// If the run is sparse we make it read from the null
		// reader.
		if is_sparse && run.RelativeUrnOffset == 0 {
			reader_run.IsSparse = true
			reader_run.Reader = &NullReader{}
		}

		result.runs = append(result.runs, reader_run)
		file_offset += reader_run.Length
	}

	return result
}

func NewCompressedRangeReader(
	runs []*Run,
	cluster_size int64,
	disk_reader io.ReaderAt,
	compression_unit_size int64) *RangeReader {

	return &RangeReader{
		runs: consumeRuns(runs, cluster_size,
			disk_reader, compression_unit_size),
	}
}

// A compression unit is the basic compression size. The compression
// unit may consist of multiple runs that provide the compressed data
// but the uncompressed size is always a compression size (normally 16
// clusters).

// Compressed runs consist of sequences of real runs followed by
// sparse runs that both represent a compressed run. For example:
// Disk Offset 7215396  RelativeUrnOffset 528 (Length 10)
// Disk Offset 7215396  RelativeUrnOffset 0 (Length 6)

// Alternative there may be multiple runs that add up to a compression
// size.
//
// Disk Offset 2769964  RelativeUrnOffset 10 (Length 1)
// Disk Offset 1391033  RelativeUrnOffset -1378931 (Length 8)
// Disk Offset 1391033  RelativeUrnOffset 0 (Length 7)

// consumeRuns consumes whole compression units from the runs and
// combines those runs into a single compressed run.
func consumeRuns(runs []*Run, cluster_size int64,
	disk_reader io.ReaderAt,
	compression_unit_size int64) []*MappedReader {

	var file_offset int64

	result := []*MappedReader{}

	for idx := 0; idx < len(runs); idx++ {
		run := runs[idx]

		// Ignore this run since it has no length.
		if run.Length == 0 {
			continue
		}

		// Only one run left - it can not be compressed but may be sparse.
		if idx+1 >= len(runs) {
			reader_run := &MappedReader{
				FileOffset:   file_offset,
				TargetOffset: run.Offset, // Offset of run on disk

				// Take up the entire compression unit
				Length:      run.Length,
				ClusterSize: cluster_size,
				IsSparse:    run.RelativeUrnOffset == 0,
				Reader:      disk_reader,
			}

			// Sparse runs read from the null reader.
			if reader_run.IsSparse {
				reader_run.Reader = &NullReader{}
			}

			result = append(result, reader_run)
			file_offset += reader_run.Length
			continue
		}

		// Break up a run larger than compression size into a regular run
		// and a potentially compressed run.
		if run.Length >= compression_unit_size {
			// Insert a run which is whole compression_unit_size
			// as large as possible.
			new_run := &MappedReader{
				FileOffset:   file_offset,
				TargetOffset: run.Offset, // Offset of run on disk
				Length:       run.Length - run.Length%compression_unit_size,
				ClusterSize:  cluster_size,
				Reader:       disk_reader,
			}

			// If the run is sparse we make it read from the null
			// reader.
			if run.RelativeUrnOffset == 0 {
				new_run.IsSparse = true
				new_run.Reader = &NullReader{}
			}

			result = append(result, new_run)
			file_offset += new_run.Length

			// Adjust the size of the next run.
			run.Offset = new_run.TargetOffset + new_run.Length
			run.Length = run.Length - new_run.Length

			// Reconsider this run again.
			idx--
			continue
		}

		// Gather runs into a compression unit
		compression_unit := []*Run{}
		total_size := int64(0)
		total_compression_unit_length := int64(0)
		last_run_is_sparse := false
		for i := idx; i < len(runs); i++ {
			run := runs[i]
			if run.RelativeUrnOffset != 0 {
				compression_unit = append(compression_unit, run)
				total_compression_unit_length += run.Length
			} else {
				last_run_is_sparse = true
			}

			total_size += run.Length
			if total_size >= compression_unit_size {
				break
			}
		}

		debugLZNT1Decompress("total_size %v, Runs %v, last_run_is_sparse %v\n",
			total_size, compression_unit, last_run_is_sparse)

		for idx, c := range compression_unit {
			debugLZNT1Decompress("compression_unit %d: %v\n", idx, c)
		}

		if last_run_is_sparse && total_size == compression_unit_size {
			// Insert a compression run.
			new_run := &MappedReader{
				FileOffset:   file_offset,
				TargetOffset: run.Offset, // Offset of run on disk

				// Take up the entire compression unit
				Length:           compression_unit_size,
				CompressedLength: run.Length,
				ClusterSize:      cluster_size,
				IsSparse:         false,
				Reader:           disk_reader,
			}
			result = append(result, new_run)
			file_offset += new_run.Length

			if len(compression_unit) > 1 {
				// Create new mappings for the compression_unit
				new_run.CompressedLength = total_compression_unit_length
				new_run.TargetOffset = 0
				ranged_reader := &RangeReader{}

				new_run.Reader = ranged_reader
				offset := int64(0)
				for _, r := range compression_unit {
					ranged_reader.runs = append(
						ranged_reader.runs, &MappedReader{
							FileOffset:       offset,
							TargetOffset:     r.Offset,
							Length:           r.Length,
							CompressedLength: 0,
							ClusterSize:      cluster_size,
							IsSparse:         false,
							Reader:           disk_reader,
						})
					offset += r.Length
				}
			}
		}

		idx += len(compression_unit)
	}

	return result
}

func (self *RangeReader) readFromARun(
	run_idx int,
	buf []byte,
	run_offset int) (int, error) {

	//	Printf("readFromARun %v\n", self.runs[run_idx])

	run := self.runs[run_idx]
	target_offset := run.TargetOffset * run.ClusterSize
	is_compressed := run.CompressedLength > 0

	if is_compressed {
		decompressed, err := run.Decompress(run.Reader, run.ClusterSize)
		if err != nil {
			return 0, err
		}
		DebugPrint("Decompressed %d from %v\n", len(decompressed), run)

		i := 0
		for {
			if run_offset >= len(decompressed) ||
				i >= len(buf) {
				return i, nil
			}

			buf[i] = decompressed[run_offset]
			run_offset++
			i++
		}

	} else {
		to_read := run.Length*run.ClusterSize - int64(run_offset)
		if int64(len(buf)) < to_read {
			to_read = int64(len(buf))
		}

		// Run contains data - read it
		// into the buffer.
		n, err := run.Reader.ReadAt(
			buf[:to_read], target_offset+int64(run_offset))
		return n, err
	}
}

func (self *RangeReader) IsFixed(offset int64) bool {
	for j := 0; j < len(self.runs); j++ {
		run := self.runs[j]

		// Start of run in bytes in file address space
		run_file_offset := run.FileOffset * run.ClusterSize
		run_length := run.Length * run.ClusterSize

		// End of run in bytes in file address space.
		run_end_file_offset := run_file_offset + run_length

		// This run can provide us with some data.
		if run_file_offset <= offset &&
			offset < run_end_file_offset {
			run_offset := offset - run_file_offset
			return IsFixed(run, run_offset)
		}
	}
	return false
}

func (self *RangeReader) VtoP(offset int64) int64 {
	for j := 0; j < len(self.runs); j++ {
		run := self.runs[j]

		// Start of run in bytes in file address space
		run_file_offset := run.FileOffset * run.ClusterSize
		run_length := run.Length * run.ClusterSize

		// End of run in bytes in file address space.
		run_end_file_offset := run_file_offset + run_length

		// This run can provide us with some data.
		if run_file_offset <= offset &&
			offset < run_end_file_offset {

			// The relative offset within the run.
			run_offset := offset - run_file_offset
			return VtoP(run, run_offset) + offset
		}
	}
	return 0
}

func (self *RangeReader) ReadAt(buf []byte, file_offset int64) (
	int, error) {
	buf_idx := 0

	// Empirically we find this is rarely > 10 so a linear search is
	// fast enough.
	run_length := len(self.runs)

	// Find the run which covers the required offset.
	for j := 0; j < run_length && buf_idx < len(buf); j++ {
		run := self.runs[j]

		// Start of run in bytes in file address space
		run_file_offset := run.FileOffset * run.ClusterSize
		run_length := run.Length * run.ClusterSize

		// End of run in bytes in file address space.
		run_end_file_offset := run_file_offset + run_length

		// This run can provide us with some data.
		if run_file_offset <= file_offset &&
			file_offset < run_end_file_offset {

			// The relative offset within the run.
			run_offset := int(file_offset - run_file_offset)

			n, err := self.readFromARun(j, buf[buf_idx:], run_offset)
			if err != nil {
				DebugPrint("Reading offset %v from run %v returned error %v\n",
					run_offset, self.runs[j].DebugString(), err)
				return buf_idx, err
			}

			if n == 0 {
				DebugPrint("Reading run %v returned no data\n", self.runs[j])
				return buf_idx, io.EOF
			}

			buf_idx += n
			file_offset += int64(n)
		}
	}

	if buf_idx == 0 {
		return 0, io.EOF
	}

	return buf_idx, nil
}

func (self *FILE_NAME) Name() string {
	return ParseUTF16String(self.Reader,
		self.Offset+self.Profile.Off_FILE_NAME_name,
		CapInt64(int64(self._length_of_name())*2, MAX_ATTR_NAME_LENGTH))
}

func (self *INDEX_NODE_HEADER) GetRecords(ntfs *NTFSContext) []*INDEX_RECORD_ENTRY {
	result := []*INDEX_RECORD_ENTRY{}

	end := int64(self.Offset_to_end_index_entry()) + self.Offset
	start := int64(self.Offset_to_index_entry()) + self.Offset

	// Need to fit the last entry in - it should be at least size of FILE_NAME
	dummy_record := self.Profile.FILE_NAME(self.Reader, 0)

	for i := start; i+int64(dummy_record.Size()) < end; {
		record := self.Profile.INDEX_RECORD_ENTRY(self.Reader, i)
		result = append(result, record)

		// Records have varied sizes.
		size_of_record := int64(record.SizeOfIndexEntry())
		if size_of_record == 0 {
			break
		}

		i += size_of_record
	}

	return result
}

func (self *ATTRIBUTE_LIST_ENTRY) Attributes(
	ntfs *NTFSContext,
	mft_entry *MFT_ENTRY,
	attr *NTFS_ATTRIBUTE) []*NTFS_ATTRIBUTE {
	result := []*NTFS_ATTRIBUTE{}

	attribute_size := attr.DataSize()
	offset := int64(0)
	for {
		attr_list_entry := self.Profile.ATTRIBUTE_LIST_ENTRY(
			self.Reader, self.Offset+offset)

		DebugPrint("%v ATTRIBUTE_LIST_ENTRY %v\n", mft_entry.Record_number(),
			DebugString(attr_list_entry, ""))

		// The attribute_list_entry points to a different MFT
		// entry than the one we are working on now. We need
		// to fetch it from there.
		mft_ref := attr_list_entry.MftReference()
		if mft_ref != uint64(mft_entry.Record_number()) {

			DebugPrint("While working on %v - Fetching from MFT Entry %v\n",
				mft_entry.Record_number(), mft_ref)
			attr, err := attr_list_entry.GetAttribute(ntfs)
			if err != nil {
				DebugPrint("Error %v\n", err)
				break
			}
			result = append(result, attr)
		}
		length := int64(attr_list_entry.Length())
		if length <= 0 {
			break
		}

		offset += length

		if offset >= attribute_size {
			break
		}

	}

	return result
}

func (self *ATTRIBUTE_LIST_ENTRY) GetAttribute(
	ntfs *NTFSContext) (*NTFS_ATTRIBUTE, error) {
	mytype := uint64(self.Type())
	myid := self.Attribute_id()

	mft, err := ntfs.GetMFT(int64(self.MftReference()))
	if err != nil {
		return nil, err
	}
	res, err := mft.GetDirectAttribute(ntfs, mytype, uint16(myid))
	if err != nil {
		DebugPrint("MFT %v not found in target\n", mft.Record_number())
	} else {
		DebugPrint("Found %v\n", DebugString(res, "  "))
	}
	return res, err
}

// The STANDARD_INDEX_HEADER has a second layer of fixups.
func DecodeSTANDARD_INDEX_HEADER(
	ntfs *NTFSContext, reader io.ReaderAt, offset int64, length int64) (
	*STANDARD_INDEX_HEADER, error) {

	// Read the entire data into a buffer.
	buffer := make([]byte, CapInt64(length, MAX_IDX_SIZE))
	n, err := reader.ReadAt(buffer, offset)
	if err != nil && err != io.EOF {
		return nil, err
	}
	buffer = buffer[:n]

	index := ntfs.Profile.STANDARD_INDEX_HEADER(reader, offset)

	fixup_offset := offset + int64(index.Fixup_offset())
	fixup_count := index.Fixup_count()
	if fixup_count > 0 {
		fixup_table := make([]byte, fixup_count*2)
		_, err = reader.ReadAt(fixup_table, fixup_offset)
		if err != nil && err != io.EOF {
			return nil, err
		}

		fixup_magic := []byte{fixup_table[0], fixup_table[1]}
		sector_idx := 0
		for idx := 2; idx < len(fixup_table); idx += 2 {
			fixup_offset := (sector_idx+1)*512 - 2
			if fixup_offset+1 >= len(buffer) ||
				buffer[fixup_offset] != fixup_magic[0] ||
				buffer[fixup_offset+1] != fixup_magic[1] {
				return nil, errors.New("Fixup error with MFT")
			}

			// Apply the fixup
			buffer[fixup_offset] = fixup_table[idx]
			buffer[fixup_offset+1] = fixup_table[idx+1]
			sector_idx += 1
		}
	}

	fixed_up_index := ntfs.Profile.STANDARD_INDEX_HEADER(
		bytes.NewReader(buffer), 0)

	// Produce a new STANDARD_INDEX_HEADER record with a fixed up
	// page.
	return fixed_up_index, nil
}

type NullReader struct{}

func (self *NullReader) ReadAt(buf []byte, offset int64) (int, error) {
	for i := 0; i < len(buf); i++ {
		buf[i] = 0
	}

	return len(buf), nil
}
