package parser

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"
)

var (
	notAvailableError = errors.New("Not available")
)

func (self *MFT_ENTRY) EnumerateAttributes(ntfs *NTFSContext) []*NTFS_ATTRIBUTE {
	offset := int64(self.Attribute_offset())
	result := make([]*NTFS_ATTRIBUTE, 0, 16)

	for {
		// Instantiate the attribute over the fixed up address space.
		attribute := self.Profile.NTFS_ATTRIBUTE(
			self.Reader, offset)

		// Reached the end of the MFT entry.
		mft_size := int64(self.Mft_entry_size())
		attribute_size := int64(attribute.Length())
		if attribute_size == 0 ||
			attribute_size+offset > mft_size {
			break
		}

		// This is an $ATTRIBUTE_LIST attribute - append its
		// own attributes to this one.
		if attribute.Type().Name == "$ATTRIBUTE_LIST" {
			attr_list := self.Profile.ATTRIBUTE_LIST_ENTRY(
				attribute.Data(ntfs), 0)

			attr_list_members := attr_list.Attributes(
				ntfs, self, attribute)

			result = append(result, attr_list_members...)
		}

		result = append(result, attribute)

		// Go to the next attribute.
		offset += int64(attribute.Length())
	}

	return result
}

// See https://github.com/CCXLabs/CCXDigger/issues/13

// It is possible that an attribute list is pointing to an mft entry
// which also contains an attribute list. The second attribute list
// may also point to another entry inside the first MFT entry. This
// causes an infinite loop.

// Previous versions of the code erroneously called
// EnumerateAttributes to resolve a foreign attribute reference but
// this is not strictly correct because a foreign reference is never
// indirect and so never should traverse ATTRIBUTE_LISTs recursively
// anyway.

// The GetDirectAttribute() function looks for an exact attribute and
// type inside an MFT entry without following any attribute
// lists. This breaks the recursion and is a more correct approach.

// Search the MFT entry for a contained attribute - does not expand
// ATTRIBUTE_LISTs. This version is suitable to be called from within
// an ATTRIBUTE_LIST expansion.
func (self *MFT_ENTRY) GetDirectAttribute(
	ntfs *NTFSContext, attr_type uint64, attr_id uint16) (*NTFS_ATTRIBUTE, error) {
	offset := int64(self.Attribute_offset())

	for {
		// Instantiate the attribute over the fixed up address space.
		attribute := self.Profile.NTFS_ATTRIBUTE(self.Reader, offset)

		// Reached the end of the MFT entry.
		mft_size := int64(self.Mft_entry_size())
		attribute_size := int64(attribute.Length())
		if attribute_size == 0 ||
			attribute_size+offset > mft_size {
			break
		}

		if attribute.Type().Value == attr_type &&
			attribute.Attribute_id() == attr_id {
			return attribute, nil
		}

		// Go to the next attribute.
		offset += int64(attribute.Length())
	}
	return nil, errors.New("No attribute found.")
}

// Open the MFT entry specified by a path name. Walks all directory
// indexes in the path to find the right MFT entry.
func (self *MFT_ENTRY) Open(ntfs *NTFSContext, filename string) (*MFT_ENTRY, error) {
	filename = strings.Replace(filename, "\\", "/", -1)
	filename = strings.Split(filename, ":")[0] // remove ADS if any as not needed
	components := strings.Split(path.Clean(filename), "/")

	get_path_in_dir := func(component string, dir *MFT_ENTRY) (
		*MFT_ENTRY, error) {

		// NTFS is usually case insensitive.
		component = strings.ToLower(component)

		for _, idx_record := range dir.Dir(ntfs) {
			item_name := strings.ToLower(idx_record.File().Name())

			if item_name == component {
				return ntfs.GetMFT(int64(
					idx_record.MftReference()))
			}
		}

		return nil, errors.New("Not found")
	}

	directory := self
	for _, component := range components {
		if component == "" {
			continue
		}
		next, err := get_path_in_dir(component, directory)
		if err != nil {
			return nil, err
		}
		directory = next
	}

	return directory, nil
}

func (self *MFT_ENTRY) Display(ntfs *NTFSContext) string {
	result := []string{self.DebugString()}

	result = append(result, "Attribute:")
	for _, attr := range self.EnumerateAttributes(ntfs) {
		result = append(result, attr.PrintStats(ntfs))
	}

	return fmt.Sprintf("[MFT_ENTRY] @ %#0x\n", self.Offset) +
		strings.Join(result, "\n")
}

// Extract the $STANDARD_INFORMATION attribute from the MFT.
func (self *MFT_ENTRY) StandardInformation(ntfs *NTFSContext) (
	*STANDARD_INFORMATION, error) {
	for _, attr := range self.EnumerateAttributes(ntfs) {
		if attr.Type().Value == ATTR_TYPE_STANDARD_INFORMATION {
			return self.Profile.STANDARD_INFORMATION(
				attr.Data(ntfs), 0), nil
		}
	}

	return nil, errors.New("$STANDARD_INFORMATION not found!")
}

// Extract the $FILE_NAME attribute from the MFT.
func (self *MFT_ENTRY) FileName(ntfs *NTFSContext) []*FILE_NAME {
	result := []*FILE_NAME{}
	for _, attr := range self.EnumerateAttributes(ntfs) {
		if attr.Type().Value == ATTR_TYPE_FILE_NAME {
			res := self.Profile.FILE_NAME(attr.Data(ntfs), 0)
			result = append(result, res)
		}
	}
	return result
}

// Retrieve the content of the attribute stream specified by type and
// id. If id is 0 return the first attribute of this type.
func (self *MFT_ENTRY) GetAttribute(
	ntfs *NTFSContext, attr_type,
	id int64, stream string) (*NTFS_ATTRIBUTE, error) {
	for _, attr := range self.EnumerateAttributes(ntfs) {
		if attr.Type().Value == uint64(attr_type) {
			if id <= 0 || int64(attr.Attribute_id()) == id {
				// Optionally allow the caller to specify the stream
				// name.
				if stream != "" && stream != attr.Name() {
					continue
				}
				return attr, nil
			}
		}
	}

	return nil, errors.New("Attribute not found!")
}

func (self *MFT_ENTRY) IsDir(ntfs *NTFSContext) bool {
	result := false
	for _, attr := range self.EnumerateAttributes(ntfs) {
		switch attr.Type().Value {
		case ATTR_TYPE_INDEX_ROOT, ATTR_TYPE_INDEX_ALLOCATION:
			return true
		}
	}
	return result
}

func (self *MFT_ENTRY) Dir(ntfs *NTFSContext) []*INDEX_RECORD_ENTRY {
	result := []*INDEX_RECORD_ENTRY{}

	for _, node := range self.DirNodes(ntfs) {
		result = append(result, node.GetRecords(ntfs)...)
	}
	return result
}

func (self *MFT_ENTRY) DirNodes(ntfs *NTFSContext) []*INDEX_NODE_HEADER {
	result := []*INDEX_NODE_HEADER{}

	for _, attr := range self.EnumerateAttributes(ntfs) {
		switch attr.Type().Value {
		case ATTR_TYPE_INDEX_ROOT:
			index_root := self.Profile.INDEX_ROOT(
				attr.Data(ntfs), 0)
			result = append(result, index_root.Node())

		case ATTR_TYPE_INDEX_ALLOCATION:
			attr_reader := attr.Data(ntfs)
			for i := int64(0); i < int64(attr.DataSize()); i += 0x1000 {
				index_root, err := DecodeSTANDARD_INDEX_HEADER(
					ntfs, attr_reader, i, 0x1000)
				if err == nil {
					result = append(result, index_root.Node())
				}
			}
		}

	}
	return result
}

type GenericRun struct {
	Offset int64
	End    int64
	Reader io.ReaderAt
}

// Stitch together several different readers mapped at different
// offsets.  In NTFS, a file's data consists of multiple $DATA
// streams, each having the same id. These different streams are
// mapped at different runlist_vcn_start to runlist_vcn_end (VCN =
// Virtual Cluster Number: the cluster number within the file's
// data). This reader combines these different readers into a single
// continuous form.
type MapReader struct {
	// Very simple for now but faster for small number of runs.
	Runs []*GenericRun
}

func (self *MapReader) partialRead(buf []byte, offset int64) (int, error) {
	DebugPrint("MapReader.partialRead %v @ %v\n", len(buf), offset)

	if len(buf) > 0 {
		for _, run := range self.Runs {
			if run.Offset <= offset && offset < run.End {
				available := run.End - offset
				to_read := int64(len(buf))
				if to_read > available {
					to_read = available
				}

				return run.Reader.ReadAt(
					buf[:to_read], offset-run.Offset)
			}
		}
	}
	return 0, io.EOF
}

func (self *MapReader) ReadAt(buf []byte, offset int64) (int, error) {
	to_read := len(buf)
	idx := int(0)

	for to_read > 0 {
		res, err := self.partialRead(buf[idx:], offset+int64(idx))
		if err != nil {
			return idx, err
		}

		to_read -= res
		idx += res
	}

	return idx, nil
}

type MFTHighlight struct {
	EntryNumber          int64
	Inode                string
	SequenceNumber       uint16
	InUse                bool
	ParentEntryNumber    uint64
	ParentSequenceNumber uint16
	FileNames            []string
	_FileNameTypes       []string
	FileSize             int64
	ReferenceCount       int64
	IsDir                bool
	HasADS               bool
	SI_Lt_FN             bool
	USecZeros            bool
	Copied               bool
	SIFlags              string
	Created0x10          time.Time
	Created0x30          time.Time
	LastModified0x10     time.Time
	LastModified0x30     time.Time
	LastRecordChange0x10 time.Time
	LastRecordChange0x30 time.Time
	LastAccess0x10       time.Time
	LastAccess0x30       time.Time

	LogFileSeqNum uint64

	// Hold on to these for delayed lazy evaluation.
	ntfs_ctx   *NTFSContext
	mft_entry  *MFT_ENTRY
	ads_name   string
	components []string
}

// Copy the struct safely replacing the mutex
func (self *MFTHighlight) Copy() *MFTHighlight {
	return &MFTHighlight{
		EntryNumber:          self.EntryNumber,
		SequenceNumber:       self.SequenceNumber,
		InUse:                self.InUse,
		ParentEntryNumber:    self.ParentEntryNumber,
		ParentSequenceNumber: self.ParentSequenceNumber,
		FileNames:            self.FileNames,
		_FileNameTypes:       self._FileNameTypes,
		FileSize:             self.FileSize,
		ReferenceCount:       self.ReferenceCount,
		IsDir:                self.IsDir,
		HasADS:               self.HasADS,
		SI_Lt_FN:             self.SI_Lt_FN,
		USecZeros:            self.USecZeros,
		Copied:               self.Copied,
		SIFlags:              self.SIFlags,
		Created0x10:          self.Created0x10,
		Created0x30:          self.Created0x30,
		LastModified0x10:     self.LastModified0x10,
		LastModified0x30:     self.LastModified0x30,
		LastRecordChange0x10: self.LastRecordChange0x10,
		LastRecordChange0x30: self.LastRecordChange0x30,
		LastAccess0x10:       self.LastAccess0x10,
		LastAccess0x30:       self.LastAccess0x30,
		LogFileSeqNum:        self.LogFileSeqNum,

		ntfs_ctx:  self.ntfs_ctx,
		mft_entry: self.mft_entry,
		ads_name:  self.ads_name,
	}
}

func (self *MFTHighlight) FullPath() string {
	return "/" + path.Join(self.Components()...)
}

func (self *MFTHighlight) Links() []string {
	components := GetHardLinks(self.ntfs_ctx, uint64(self.EntryNumber),
		DefaultMaxLinks)
	result := make([]string, 0, len(components))
	for _, l := range components {
		result = append(result, strings.Join(l, "\\"))
	}
	return result
}

func (self *MFTHighlight) FileNameTypes() string {
	return strings.Join(self._FileNameTypes, ",")
}

func (self *MFTHighlight) FileName() string {
	short_name := ""
	for idx, name := range self.FileNames {
		name_type := self._FileNameTypes[idx]
		switch name_type {
		case "Win32", "DOS+Win32", "POSIX":
			return name
		default:
			short_name = name
		}
	}

	return short_name
}

// For simplicity and backwards compatibility returns the first hard
// link of the mft entry. In NTFS MFT entries can have multiple paths
// so you should consult the Links() to get more info.
func (self *MFTHighlight) Components() []string {
	components := []string{}
	links := GetHardLinks(self.ntfs_ctx, uint64(self.EntryNumber), 1)
	if len(links) > 0 {
		components = links[0]
	}

	if self.ads_name != "" {
		return setADS(components, self.ads_name)
	}

	return components
}

func ParseMFTFile(
	ctx context.Context,
	reader io.ReaderAt,
	size int64,
	cluster_size int64,
	record_size int64) chan *MFTHighlight {
	return ParseMFTFileWithOptions(ctx, reader, size,
		cluster_size, record_size, 0, GetDefaultOptions())
}

func ParseMFTFileWithOptions(
	ctx context.Context,
	reader io.ReaderAt,
	size int64,
	cluster_size int64,
	record_size int64,
	start_entry int64,
	options Options) chan *MFTHighlight {
	output := make(chan *MFTHighlight)

	if record_size == 0 {
		close(output)
		return output
	}

	go func() {
		defer close(output)

		ntfs := newNTFSContext(&NullReader{}, "NullReader")
		defer ntfs.Close()

		ntfs.MFTReader = reader
		ntfs.ClusterSize = cluster_size
		ntfs.RecordSize = record_size
		ntfs.SetOptions(options)

		for id := start_entry; id < size/record_size+1; id++ {
			mft_entry, err := ntfs.GetMFT(id)
			if err != nil {
				continue
			}

			var file_names []*FILE_NAME
			var file_name_types []string
			var file_name_strings []string

			var si *STANDARD_INFORMATION
			var size int64
			ads := []string{}
			ads_sizes := []int64{}
			si_flags := ""

			for _, attr := range mft_entry.EnumerateAttributes(ntfs) {
				attr_type := attr.Type()
				switch attr_type.Value {
				case ATTR_TYPE_DATA:
					if size == 0 {
						size = attr.DataSize()
					}

					// Check if the stream has ADS
					attr_name := attr.Name()
					if attr_name != "" {
						ads = append(ads, attr_name)
						ads_sizes = append(ads_sizes, int64(attr.Size()))
					}

				case ATTR_TYPE_FILE_NAME:
					res := ntfs.Profile.FILE_NAME(attr.Data(ntfs), 0)
					file_names = append(file_names, res)
					file_name_types = append(file_name_types, res.NameType().Name)
					fn := res.Name()
					file_name_strings = append(file_name_strings, fn)

				case ATTR_TYPE_STANDARD_INFORMATION:
					si = ntfs.Profile.STANDARD_INFORMATION(
						attr.Data(ntfs), 0)
					si_flags = si.Flags().DebugString()
				}
			}
			if len(file_names) == 0 {
				continue
			}
			if si == nil {
				continue
			}

			mft_id := mft_entry.Record_number()
			row := &MFTHighlight{
				EntryNumber:          int64(mft_id),
				Inode:                fmt.Sprintf("%d", mft_id),
				SequenceNumber:       mft_entry.Sequence_value(),
				InUse:                mft_entry.Flags().IsSet("ALLOCATED"),
				ParentEntryNumber:    file_names[0].MftReference(),
				ParentSequenceNumber: file_names[0].Seq_num(),
				FileNames:            file_name_strings,
				_FileNameTypes:       file_name_types,
				FileSize:             size,
				ReferenceCount:       int64(mft_entry.Link_count()),
				IsDir:                mft_entry.Flags().IsSet("DIRECTORY"),
				HasADS:               len(ads) > 0,
				SIFlags:              si_flags,
				Created0x10:          si.Create_time().Time,
				Created0x30:          file_names[0].Created().Time,
				LastModified0x10:     si.File_altered_time().Time,
				LastModified0x30:     file_names[0].File_modified().Time,
				LastRecordChange0x10: si.Mft_altered_time().Time,
				LastRecordChange0x30: file_names[0].Mft_modified().Time,
				LastAccess0x10:       si.File_accessed_time().Time,
				LastAccess0x30:       file_names[0].File_accessed().Time,
				LogFileSeqNum:        mft_entry.Logfile_sequence_number(),

				ntfs_ctx:  ntfs,
				mft_entry: mft_entry,
			}

			row.SI_Lt_FN = row.Created0x10.Before(row.Created0x30)
			row.USecZeros = row.Created0x10.Unix()*1000000000 ==
				row.Created0x10.UnixNano() ||
				row.LastModified0x10.Unix()*1000000000 == row.LastModified0x10.UnixNano()
			row.Copied = row.Created0x10.After(row.LastModified0x10)

			// Check for cancellations.
			select {
			case <-ctx.Done():
				return

			case output <- row:
			}

			// Duplicate ADS names so we can easily search on them.
			for idx, ads_name := range ads {
				new_row := row.Copy()

				file_names := []string{}
				// Convert all the names to have an ADS at the end
				// (long name + ":" + ads, short name + ":" + ads
				// etc).
				for _, name := range new_row.FileNames {
					file_names = append(file_names, name+":"+ads_name)
				}
				new_row.FileNames = file_names
				new_row.IsDir = false
				new_row.ads_name = ads_name
				new_row.FileSize = ads_sizes[idx]
				new_row.Inode += ":" + ads_name

				select {
				case <-ctx.Done():
					return

				case output <- new_row:
				}
			}
		}
	}()

	return output
}
