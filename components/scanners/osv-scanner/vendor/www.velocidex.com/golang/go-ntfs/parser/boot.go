package parser

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

var (
	EntryTooShortError = errors.New("EntryTooShortError")
	ShortReadError     = errors.New("ShortReadError")
)

func (self *NTFS_BOOT_SECTOR) ClusterSize() int64 {
	return int64(self._cluster_size()) * int64(self.Sector_size())
}

func (self *NTFS_BOOT_SECTOR) BlockCount() int64 {
	return int64(self._volume_size()) / int64(self.ClusterSize())
}

func (self *NTFS_BOOT_SECTOR) RecordSize() int64 {
	_record_size := int64(self._mft_record_size())
	if _record_size > 0 {
		return _record_size * self.ClusterSize()
	}
	return 1 << uint32(-_record_size)
}

// The MFT entry needs to be fixed up. This method extracts the
// MFT_ENTRY from disk into a buffer and perfoms the fixups. We then
// return an MFT_ENTRY instantiated over this fixed up buffer.
func FixUpDiskMFTEntry(mft *MFT_ENTRY) (io.ReaderAt, error) {
	STATS.Inc_FixUpDiskMFTEntry()

	// Read the entire MFT entry into the buffer and then apply
	// the fixup table. (Maxsize uint16)
	mft_allocated_size := mft.Mft_entry_allocated()
	allocated_len := CapUint16(mft_allocated_size, MAX_MFT_ENTRY_SIZE)

	// MFT should be a reasonable size - if it is too small it is
	// probably not valid.
	if allocated_len < 0x100 {
		return nil, EntryTooShortError
	}

	buffer := make([]byte, allocated_len)
	n, err := mft.Reader.ReadAt(buffer, mft.Offset)
	if err != nil {
		return nil, err
	}
	if n < int(allocated_len) {
		return nil, ShortReadError
	}

	// The fixup table is an array of 2 byte values. The first
	// value is the magic and the rest are fixup values.
	fixup_offset := mft.Offset + int64(mft.Fixup_offset())
	fixup_count := int64(mft.Fixup_count())
	if fixup_count == 0 {
		return bytes.NewReader(buffer), nil
	}

	fixup_table_len := CapInt64(fixup_count*2, int64(allocated_len))
	fixup_table := make([]byte, fixup_table_len)
	n, err = mft.Reader.ReadAt(fixup_table, fixup_offset)
	if err != nil {
		return nil, err
	}
	if n < int(fixup_table_len) {
		return nil, errors.New("Short read")
	}

	fixup_magic := []byte{fixup_table[0], fixup_table[1]}

	sector_idx := 0
	for idx := 2; idx < len(fixup_table); idx += 2 {
		fixup_offset := (sector_idx+1)*512 - 2
		if fixup_offset+1 >= len(buffer) ||
			buffer[fixup_offset] != fixup_magic[0] ||
			buffer[fixup_offset+1] != fixup_magic[1] {
			return nil, errors.New(fmt.Sprintf("Fixup error with MFT %d",
				mft.Record_number()))
		}

		// Apply the fixup
		buffer[fixup_offset] = fixup_table[idx]
		buffer[fixup_offset+1] = fixup_table[idx+1]
		sector_idx += 1
	}

	return &FixedUpReader{
		Reader:          bytes.NewReader(buffer),
		original_offset: mft.Offset,
	}, nil
}

// Find the root MFT_ENTRY object. Returns a reader over the $MFT file.
func BootstrapMFT(ntfs *NTFSContext) (io.ReaderAt, error) {
	// The MFT is a table of MFT_ENTRY records read from an
	// abstracted reader which is itself a $DATA attribute of the
	// first MFT record:

	// MFT[0] -> Attr $DATA contains the entire $MFT stream.

	// We therefore need to bootstrap the MFT:
	// 1. Read the first entry in the first cluster using the disk reader.
	// 2. Search for the $DATA attribute.
	// 3. Reconstruct the runlist and RunReader from this attribute.
	// 4. Instantiate the MFT over this new reader.
	record_size := ntfs.Boot.ClusterSize()
	offset := int64(ntfs.Boot._mft_cluster()) * record_size

	// In the first pass we instantiate a reader of the MFT $DATA
	// stream that is found in the first MFT entry. The real MFT may
	// be larger than that and split across multiple entries but we
	// can not bootstrap it until we have the reader of the first part
	// of the MFT.
	root_mft, err := GetFixedUpMFTEntry(ntfs, ntfs.DiskReader, offset)
	if err != nil {
		return nil, err
	}

	var first_mft_reader io.ReaderAt
	found_attribute_list := false

	// Find the $DATA attribute of the root entry. This will
	// contain the full $MFT file.
	for _, attr := range root_mft.EnumerateAttributes(ntfs) {
		switch attr.Type().Value {
		case ATTR_TYPE_ATTRIBUTE_LIST:
			// If there is an attribute list the MFT may be split
			// across multiple entries - further processing will be
			// needed.
			found_attribute_list = true

		case ATTR_TYPE_DATA:
			first_mft_reader = attr.Data(ntfs)
		}
	}

	if first_mft_reader == nil {
		return nil, errors.New("$DATA attribute not found for $MFT")
	}

	// This is the common case - only one $DATA attribute.
	if !found_attribute_list {
		return first_mft_reader, nil
	}

	// There are more VCNs which we need to discover. Set the
	// MFTReader in the context to cover the first VCN only for the
	// below call to EnumerateAttributes. Hopefully the actual
	// attribute falls inside the first VCN.
	ntfs.MFTReader = first_mft_reader

	// Now do a second scan of the MFT entry to find all the
	// attributes in the attribute list (including extended
	// attributes). We depend on the first VNC to be in the $MFT entry
	// and that extended $DATA attributes will be present in this
	// first stream.
	root_mft, err = ntfs.GetMFT(0)
	if err != nil {
		return nil, err
	}

	// Collect all the data streams in the root MFT entry (include
	// extended attributes). Each $DATA stream is a VCN in the wider
	// MFT stream.
	var mft_data_streams []*NTFS_ATTRIBUTE
	for _, attr := range root_mft.EnumerateAttributes(ntfs) {
		if attr.Type().Value == ATTR_TYPE_DATA {
			mft_data_streams = append(mft_data_streams, attr)
		}
	}

	// Create a single reader over all the VCN streams.
	result := &RangeReader{
		runs: joinAllVCNs(ntfs, mft_data_streams),
	}

	// Reset the MFTReader in the context so we can read all MFT
	// entries from it (even ones in the second $DATA attribute).
	ntfs.MFTReader = result

	return result, nil
}

func (self *NTFS_BOOT_SECTOR) IsValid() error {
	if self.Magic() != 0xaa55 {
		return errors.New("Invalid magic")
	}

	switch self.ClusterSize() {
	case 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
		0x80, 0x100, 0x200, 0x400, 0x800, 0x1000,
		0x2000, 0x4000, 0x8000, 0x10000:
		break
	default:
		return errors.New(
			fmt.Sprintf("Invalid cluster size %x",
				self.ClusterSize()))
	}

	sector_size := self.Sector_size()
	if sector_size == 0 || (sector_size%512 != 0) {
		return errors.New("Invalid sector_size")
	}

	if self.BlockCount() == 0 {
		return errors.New("Volume size is 0")
	}

	return nil
}

func GetFixedUpMFTEntry(
	ntfs *NTFSContext,
	reader io.ReaderAt, offset int64) (*MFT_ENTRY, error) {
	raw_mft := ntfs.Profile.MFT_ENTRY(reader, offset)
	fixed_up_reader, err := FixUpDiskMFTEntry(raw_mft)
	if err != nil {
		return nil, err
	}

	return ntfs.Profile.MFT_ENTRY(fixed_up_reader, 0), nil
}
