// Implement some easy APIs.
package parser

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// An invalid filename to flag a wildcard search.
	WILDCARD_STREAM_NAME = ":*:"
	WILDCARD_STREAM_ID   = uint16(0xffff)
)

var (
	FILE_NOT_FOUND_ERROR = errors.New("File not found.")
)

type FileInfo struct {
	MFTId          string    `json:"MFTId,omitempty"`
	SequenceNumber uint16    `json:"SequenceNumber,omitempty"`
	Mtime          time.Time `json:"Mtime,omitempty"`
	Atime          time.Time `json:"Atime,omitempty"`
	Ctime          time.Time `json:"Ctime,omitempty"`
	Btime          time.Time `json:"Btime,omitempty"` // Birth time.
	FNBtime        time.Time `json:"FNBtime,omitempty"`
	FNMtime        time.Time `json:"FNBtime,omitempty"`
	Name           string    `json:"Name,omitempty"`
	NameType       string    `json:"NameType,omitempty"`
	ExtraNames     []string  `json:"ExtraNames,omitempty"`
	IsDir          bool      `json:"IsDir,omitempty"`
	Size           int64
	AllocatedSize  int64

	// Is it in I30 slack?
	IsSlack     bool  `json:"IsSlack,omitempty"`
	SlackOffset int64 `json:"SlackOffset,omitempty"`
}

func GetNTFSContext(image io.ReaderAt, offset int64) (*NTFSContext, error) {
	ntfs := newNTFSContext(image, "GetNTFSContext")

	// NTFS Parsing starts with the boot record.
	ntfs.Boot = &NTFS_BOOT_SECTOR{Reader: image,
		Profile: ntfs.Profile, Offset: offset}

	err := ntfs.Boot.IsValid()
	if err != nil {
		return nil, err
	}

	ntfs.ClusterSize = ntfs.Boot.ClusterSize()

	mft_reader, err := BootstrapMFT(ntfs)
	if err != nil {
		return nil, err
	}

	ntfs.MFTReader = mft_reader

	return ntfs, nil
}

func ParseMFTId(mft_id string) (mft_idx int64, attr int64, id int64, stream_name string, err error) {
	stream_name = WILDCARD_STREAM_NAME

	// Support the ADS name being included in the inode
	parts := strings.SplitN(mft_id, ":", 2)
	if len(parts) > 1 {
		stream_name = parts[1]
	}
	components := []int64{}
	components_str := strings.Split(parts[0], "-")
	for _, component_str := range components_str {
		x, err := strconv.Atoi(component_str)
		if err != nil {
			return 0, 0, 0, "", errors.New("Incorrect format for MFTId: e.g. 5-144-1")
		}

		components = append(components, int64(x))
	}

	switch len(components) {
	case 1:
		// 0xffff is the wildcard stream id - means pick the first one.
		return components[0], ATTR_TYPE_DATA, 0xffff, stream_name, nil
	case 2:
		return components[0], components[1], 0xffff, stream_name, nil
	case 3:
		return components[0], components[1], components[2], stream_name, nil
	default:
		return 0, 0, 0, "", errors.New("Incorrect format for MFTId: e.g. 5-144-1")
	}
}

func GetDataForPath(ntfs *NTFSContext, path string) (RangeReaderAt, error) {
	// Check for ADS in the path.
	stream_name := WILDCARD_STREAM_NAME

	parts := strings.SplitN(path, ":", 2)
	if len(parts) > 1 {
		stream_name = parts[1]
	}

	root, err := ntfs.GetMFT(5)
	if err != nil {
		return nil, err
	}

	mft_entry, err := root.Open(ntfs, parts[0])
	if err != nil {
		return nil, err
	}

	return OpenStream(ntfs, mft_entry,
		ATTR_TYPE_DATA, WILDCARD_STREAM_ID, stream_name)
}

func RangeSize(rng RangeReaderAt) int64 {
	runs := rng.Ranges()
	if len(runs) == 0 {
		return 0
	}

	last_run := runs[len(runs)-1]
	return last_run.Offset + last_run.Length
}

func Stat(ntfs *NTFSContext, node_mft *MFT_ENTRY) []*FileInfo {
	var si *STANDARD_INFORMATION
	var other_file_names []*FILE_NAME
	var data_attributes []*NTFS_ATTRIBUTE
	var win32_name *FILE_NAME
	var index_attribute *NTFS_ATTRIBUTE
	var fn_birth_time, fn_mtime time.Time

	mft_id := node_mft.Record_number()
	is_dir := node_mft.Flags().IsSet("DIRECTORY")

	// Walk all the attributes collecting the imporant things.
	for _, attr := range node_mft.EnumerateAttributes(ntfs) {
		switch attr.Type().Value {
		case ATTR_TYPE_STANDARD_INFORMATION:
			si = ntfs.Profile.STANDARD_INFORMATION(attr.Data(ntfs), 0)

		case ATTR_TYPE_FILE_NAME:
			// Separate the filenames into LFN and other file names.
			file_name := ntfs.Profile.FILE_NAME(attr.Data(ntfs), 0)

			// The birth of an MFT is determined by the
			// $FILE_NAME streams File_modified attribute
			// since it can not modified using normal
			// APIs.
			fn_birth_time = file_name.Created().Time
			fn_mtime = file_name.Created().Time

			switch file_name.NameType().Name {
			case "POSIX", "Win32", "DOS+Win32":
				win32_name = file_name
			default:
				other_file_names = append(
					other_file_names, file_name)
			}

		case ATTR_TYPE_DATA:
			// Only show the first VCN run of
			// non-resident $DATA attributes.
			if !attr.IsResident() &&
				attr.Runlist_vcn_start() != 0 {
				continue
			}

			data_attributes = append(data_attributes, attr)

		case ATTR_TYPE_INDEX_ROOT, ATTR_TYPE_INDEX_ALLOCATION:
			index_attribute = attr
		}
	}

	// We need the si for the timestamps.
	if si == nil || win32_name == nil {
		return nil
	}

	// Now generate multiple file info for streams we want to be
	// distinct.
	result := []*FileInfo{}

	add_extra_names := func(info *FileInfo, ads string) {
		for _, name := range other_file_names {
			extra_name := name.Name()
			info.ExtraNames = append(info.ExtraNames, extra_name+ads)

			if !strings.Contains(extra_name, "~") {
				// Make a copy
				info_copy := *info
				info_copy.Name = extra_name + ads
				info_copy.ExtraNames = []string{win32_name.Name() + ads}
				result = append(result, &info_copy)
			}
		}
	}

	if index_attribute != nil {
		inode := fmt.Sprintf(
			"%d-%d-%d", mft_id,
			index_attribute.Type().Value,
			index_attribute.Attribute_id())

		info := &FileInfo{
			MFTId:          inode,
			SequenceNumber: node_mft.Sequence_value(),
			Mtime:          si.File_altered_time().Time,
			Atime:          si.File_accessed_time().Time,
			Ctime:          si.Mft_altered_time().Time,
			Btime:          si.Create_time().Time,
			FNBtime:        fn_birth_time,
			FNMtime:        fn_mtime,
			Name:           win32_name.Name(),
			NameType:       win32_name.NameType().Name,
			IsDir:          is_dir,
		}

		add_extra_names(info, "")
		result = append(result, info)
	}

	inode_formatter := InodeFormatter{}
	for _, attr := range data_attributes {
		ads := ""
		name := attr.Name()
		switch name {
		case "$I30", "":
			ads = ""
		default:
			ads = ":" + name
		}

		attr_id := attr.Attribute_id()
		attr_type_id := attr.Type().Value

		info := &FileInfo{
			MFTId: inode_formatter.Inode(
				mft_id, attr_type_id, attr_id, name),
			SequenceNumber: node_mft.Sequence_value(),
			Mtime:          si.File_altered_time().Time,
			Atime:          si.File_accessed_time().Time,
			Ctime:          si.Mft_altered_time().Time,
			Btime:          si.Create_time().Time,
			FNBtime:        fn_birth_time,
			FNMtime:        fn_mtime,
			Name:           win32_name.Name() + ads,
			NameType:       win32_name.NameType().Name,
			IsDir:          is_dir,
			Size:           attr.DataSize(),
		}

		add_extra_names(info, ads)

		// Since ADS are actually data streams they can not be
		// directories themselves. The underlying file info will still
		// be a directory.
		if ads != "" {
			info.IsDir = false
		}

		result = append(result, info)
	}

	return result
}

func ListDir(ntfs *NTFSContext, root *MFT_ENTRY) []*FileInfo {
	// The index itself stores pointers to the FILE_NAME entry for
	// each MFT. Therefore there are usually 2 references to the
	// same MFT entry. We de-duplicate these references because we
	// list each MFT entirely separately.
	seen := make(map[int64]bool)
	result := []*FileInfo{}

	for _, node := range root.Dir(ntfs) {
		node_mft_id := int64(node.MftReference())
		_, pres := seen[node_mft_id]
		if pres {
			continue
		}
		seen[node_mft_id] = true

		node_mft, err := ntfs.GetMFT(node_mft_id)
		if err != nil {
			continue
		}
		result = append(result, Stat(ntfs, node_mft)...)
	}
	return result
}

type attrInfo struct {
	attr_type uint64
	attr_id   uint16
	attr_name string
	resident  bool
	vcn_start uint64
	vcn_end   uint64
	attr      *NTFS_ATTRIBUTE
}

func selectAttribute(attributes []*attrInfo,
	attr_type uint64,
	required_attr_id uint16,
	required_data_attr_name string) (*attrInfo, error) {

	// Search for stream that matches the type.  First search for non
	// ADS stream, and if not found then search again for any stream.
	if required_data_attr_name == WILDCARD_STREAM_NAME &&
		required_attr_id == WILDCARD_STREAM_ID {
		for _, attr := range attributes {
			if attr.attr_type == attr_type && attr.attr_name == "" {
				if attr.resident || attr.vcn_start == 0 {
					return attr, nil
				}
			}
		}

		// Now search for the first attributed name.
		for _, attr := range attributes {
			if attr.attr_type == attr_type {
				if attr.resident || attr.vcn_start == 0 {
					return attr, nil
				}
			}
		}
		return nil, FILE_NOT_FOUND_ERROR
	}

	// Search for any stream with the given name
	if required_attr_id == WILDCARD_STREAM_ID {
		for _, attr := range attributes {
			if attr.attr_type == attr_type &&
				attr.attr_name == required_data_attr_name {
				if attr.resident || attr.vcn_start == 0 {
					return attr, nil
				}
			}
		}
		return nil, FILE_NOT_FOUND_ERROR
	}

	// Search for a specific attr_id.
	if required_attr_id != WILDCARD_STREAM_ID {
		for _, attr := range attributes {
			if attr.attr_type == attr_type &&
				attr.attr_id == required_attr_id {
				if required_data_attr_name != WILDCARD_STREAM_NAME &&
					required_data_attr_name != attr.attr_name {
					continue
				}

				if attr.resident || attr.vcn_start == 0 {
					return attr, nil
				}
			}
		}
	}
	return nil, FILE_NOT_FOUND_ERROR
}

// Get all VCNs having the (same type and ID for default $DATA stream)
// OR ($DATA with specific name)
func GetAllVCNs(ntfs *NTFSContext,
	mft_entry *MFT_ENTRY, attr_type uint64, required_attr_id uint16,
	required_data_attr_name string) []*NTFS_ATTRIBUTE {

	// First extract all attribute info so we can decide who to choose.
	attributes := []*attrInfo{}
	for _, attr := range mft_entry.EnumerateAttributes(ntfs) {
		attributes = append(attributes, &attrInfo{
			attr_type: attr.Type().Value,
			attr_id:   attr.Attribute_id(),
			attr_name: attr.Name(),
			resident:  attr.IsResident(),
			vcn_start: attr.Runlist_vcn_start(),
			vcn_end:   attr.Runlist_vcn_end(),
			attr:      attr,
		})
	}

	// Depending on the required_data_attr_name and required_attr_id
	// specified we select the attribute we need.
	selected_attribute, err := selectAttribute(attributes, attr_type,
		required_attr_id, required_data_attr_name)
	if err != nil {
		return nil
	}

	// Now collect all attributes with the exact set of type, id and
	// name. These all form part of the same VCN set.
	result := []*NTFS_ATTRIBUTE{selected_attribute.attr}

	// Resident attributes do not have VCNs
	if selected_attribute.resident {
		return result
	}

	for {
		selected_attribute, err = findNextVCN(attributes, selected_attribute)
		// Protect ourselves from cycles.
		if err != nil || len(result) > 20 {
			break
		}

		result = append(result, selected_attribute.attr)
	}

	return result
}

func findNextVCN(attributes []*attrInfo, selected_attribute *attrInfo) (*attrInfo, error) {
	// Make sure the vcns make sense
	if selected_attribute.vcn_end <= selected_attribute.vcn_start {
		return nil, FILE_NOT_FOUND_ERROR
	}

	for _, attr := range attributes {
		if attr.attr_type == attr.attr_type &&
			attr.vcn_start == selected_attribute.vcn_end+1 &&
			attr.attr_name == selected_attribute.attr_name {
			return attr, nil
		}
	}
	return nil, FILE_NOT_FOUND_ERROR
}

// Open the full stream. Note - In NTFS a stream can be composed of
// multiple VCN attributes: All VCN substreams have the same attribute
// type and id but different start and end VCNs. This function finds
// all related attributes and wraps them in a RangeReader to appear as
// a single stream. This function is what you need when you want to
// read the full file.
func OpenStream(ntfs *NTFSContext,
	mft_entry *MFT_ENTRY, attr_type uint64, attr_id uint16, attr_name string) (RangeReaderAt, error) {

	result := &RangeReader{}

	// Gather all the VCNs together
	vcns := GetAllVCNs(ntfs, mft_entry, attr_type, attr_id, attr_name)
	if len(vcns) == 0 {
		return nil, os.ErrNotExist
	}

	// Return a resident reader immediately.
	attr := vcns[0]

	if attr.Resident().Name == "RESIDENT" {
		buf := make([]byte, CapUint32(attr.Content_size(),
			MAX_MFT_ENTRY_SIZE))
		n, _ := attr.Reader.ReadAt(buf,
			attr.Offset+int64(attr.Content_offset()))
		buf = buf[:n]

		return &MappedReader{
			FileOffset:  0,
			Length:      int64(n),
			ClusterSize: 1,
			Reader:      bytes.NewReader(buf),
		}, nil
	}

	result.runs = joinAllVCNs(ntfs, vcns)

	return result, nil
}

func joinAllVCNs(ntfs *NTFSContext, vcns []*NTFS_ATTRIBUTE) []*MappedReader {
	actual_size := int64(0)
	initialized_size := int64(0)
	compression_unit_size := int64(0)
	runs := []*Run{}

	// Sort the VCNs in order so they can be joined.
	sort.Slice(vcns, func(i, j int) bool {
		return vcns[i].Runlist_vcn_start() < vcns[j].Runlist_vcn_start()
	})

	for _, vcn := range vcns {
		// Actual_size is only set on the first stream.
		if actual_size == 0 {
			actual_size = int64(vcn.Actual_size())
		}

		// Initialized_size is only set on the first stream
		if initialized_size == 0 {
			initialized_size = int64(vcn.Initialized_size())
		}

		// Compression_unit_size is only set on the first stream.
		if compression_unit_size == 0 {
			compression_unit_size = int64(
				1 << uint64(vcn.Compression_unit_size()))
		}

		// Join all the runlists from all VCNs into the same runlist -
		// compressed files often have their runs broken up into
		// different vcns so it is just easier to combine them before
		// parsing.
		vcn_runlist := vcn.RunList()
		runs = append(runs, vcn_runlist...)
	}

	var reader *MappedReader
	flags := vcns[0].Flags()

	if IsCompressed(flags) { // YK - all Sparse files are not compressed!
		reader = &MappedReader{
			ClusterSize: 1,
			FileOffset:  0,
			Length:      initialized_size,
			Reader: NewCompressedRangeReader(runs,
				ntfs.ClusterSize, ntfs.DiskReader,
				compression_unit_size),
		}

	} else {
		reader = &MappedReader{
			ClusterSize: 1,
			FileOffset:  0,
			Length:      initialized_size,
			Reader: NewUncompressedRangeReader(runs,
				ntfs.ClusterSize, ntfs.DiskReader, IsSparse(flags)),
		}
	}

	// If the attribute is not fully initialized, trim the mapping
	// to the initialized range and add a pad to the end to make
	// up the full length. For example, the attribute might
	// contain 32 clusters, but only 16 clusters are initialized
	// and 16 clusters are padding.
	if actual_size > initialized_size {
		return []*MappedReader{
			reader,
			// Pad starts immediately after the last range
			&MappedReader{
				ClusterSize: 1,
				FileOffset:  initialized_size,
				Length:      actual_size - initialized_size,
				IsSparse:    true,
				Reader:      &NullReader{},
			}}
	}

	return []*MappedReader{reader}
}
