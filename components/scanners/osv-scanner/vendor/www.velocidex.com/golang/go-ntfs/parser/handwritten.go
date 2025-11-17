package parser

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// These are hand written parsers for often used structs.

type NTFS_ATTRIBUTE struct {
	b       [64]byte
	Reader  io.ReaderAt
	Offset  int64
	Profile *NTFSProfile
}

func NewNTFS_ATTRIBUTE(Reader io.ReaderAt,
	Offset int64, Profile *NTFSProfile) *NTFS_ATTRIBUTE {
	result := &NTFS_ATTRIBUTE{
		Reader:  Reader,
		Offset:  Offset,
		Profile: Profile,
	}

	_, err := Reader.ReadAt(result.b[:], Offset)
	if err != nil {
		return result
	}
	return result
}

func (self *NTFS_ATTRIBUTE) Size() int {
	return 64
}

func (self *NTFS_ATTRIBUTE) Type() *Enumeration {
	value := binary.LittleEndian.Uint32(self.b[0:4])
	name := "Unknown"
	switch value {

	case 16:
		name = "$STANDARD_INFORMATION"

	case 32:
		name = "$ATTRIBUTE_LIST"

	case 48:
		name = "$FILE_NAME"

	case 64:
		name = "$OBJECT_ID"

	case 80:
		name = "$SECURITY_DESCRIPTOR"

	case 96:
		name = "$VOLUME_NAME"

	case 112:
		name = "$VOLUME_INFORMATION"

	case 128:
		name = "$DATA"

	case 144:
		name = "$INDEX_ROOT"

	case 160:
		name = "$INDEX_ALLOCATION"

	case 176:
		name = "$BITMAP"

	case 192:
		name = "$REPARSE_POINT"

	case 208:
		name = "$EA_INFORMATION"

	case 224:
		name = "$EA"

	case 256:
		name = "$LOGGED_UTILITY_STREAM"
	}
	return &Enumeration{Value: uint64(value), Name: name}
}

func (self *NTFS_ATTRIBUTE) Length() uint32 {
	return binary.LittleEndian.Uint32(self.b[4:8])
}

func (self *NTFS_ATTRIBUTE) Resident() *Enumeration {
	value := uint8(self.b[8])
	name := "Unknown"
	switch value {

	case 0:
		name = "RESIDENT"

	case 1:
		name = "NON-RESIDENT"
	}
	return &Enumeration{Value: uint64(value), Name: name}
}

func (self *NTFS_ATTRIBUTE) name_length() byte {
	return uint8(self.b[9])
}

func (self *NTFS_ATTRIBUTE) name_offset() uint16 {
	return binary.LittleEndian.Uint16(self.b[10:12])
}

func (self *NTFS_ATTRIBUTE) Flags() *EntryFlags {
	value := binary.LittleEndian.Uint16(self.b[12:14])
	res := EntryFlags(uint64(value))
	return &res
}

type EntryFlags uint64

func (self EntryFlags) DebugString() string {
	names := []string{}

	if self&(1<<0) != 0 {
		names = append(names, "COMPRESSED")
	}

	if self&(1<<14) != 0 {
		names = append(names, "ENCRYPTED")
	}

	if self&(1<<15) != 0 {
		names = append(names, "SPARSE")
	}

	return fmt.Sprintf("%d (%v)", self, strings.Join(names, ","))
}

// Faster shortcuts to avoid extra allocations.
func IsCompressed(flags *EntryFlags) bool {
	return uint64(*flags)&uint64(1) != 0
}

func IsCompressedOrSparse(flags *EntryFlags) bool {
	return uint64(*flags)&uint64(1+1<<15) != 0
}

func IsSparse(flags *EntryFlags) bool {
	return uint64(*flags)&uint64(1<<15) != 0
}

func (self *NTFS_ATTRIBUTE) Attribute_id() uint16 {
	return binary.LittleEndian.Uint16(self.b[14:16])
}

func (self *NTFS_ATTRIBUTE) Content_size() uint32 {
	return binary.LittleEndian.Uint32(self.b[16:20])
}

func (self *NTFS_ATTRIBUTE) Content_offset() uint16 {
	return binary.LittleEndian.Uint16(self.b[20:22])
}

func (self *NTFS_ATTRIBUTE) Runlist_vcn_start() uint64 {
	return binary.LittleEndian.Uint64(self.b[16:24])
}

func (self *NTFS_ATTRIBUTE) Runlist_vcn_end() uint64 {
	return binary.LittleEndian.Uint64(self.b[24:32])
}

func (self *NTFS_ATTRIBUTE) Runlist_offset() uint16 {
	return binary.LittleEndian.Uint16(self.b[32:34])
}

func (self *NTFS_ATTRIBUTE) Compression_unit_size() uint16 {
	return binary.LittleEndian.Uint16(self.b[34:36])
}

func (self *NTFS_ATTRIBUTE) Allocated_size() uint64 {
	return binary.LittleEndian.Uint64(self.b[40:48])
}

func (self *NTFS_ATTRIBUTE) Actual_size() uint64 {
	return binary.LittleEndian.Uint64(self.b[48:56])
}

func (self *NTFS_ATTRIBUTE) Initialized_size() uint64 {
	return binary.LittleEndian.Uint64(self.b[56:64])
}

func (self *NTFS_ATTRIBUTE) DebugString() string {
	result := fmt.Sprintf("struct NTFS_ATTRIBUTE @ %#x:\n", self.Offset)
	result += fmt.Sprintf("  Type: %v\n", self.Type().DebugString())
	result += fmt.Sprintf("  Length: %#0x\n", self.Length())
	result += fmt.Sprintf("  Resident: %v\n", self.Resident().DebugString())
	result += fmt.Sprintf("  name_length: %#0x\n", self.name_length())
	result += fmt.Sprintf("  name_offset: %#0x\n", self.name_offset())
	result += fmt.Sprintf("  Flags: %v\n", self.Flags().DebugString())
	result += fmt.Sprintf("  Attribute_id: %#0x\n", self.Attribute_id())
	result += fmt.Sprintf("  Content_size: %#0x\n", self.Content_size())
	result += fmt.Sprintf("  Content_offset: %#0x\n", self.Content_offset())
	if self.Resident().Value == 1 {
		result += fmt.Sprintf("  Runlist_vcn_start: %#0x\n", self.Runlist_vcn_start())
		result += fmt.Sprintf("  Runlist_vcn_end: %#0x\n", self.Runlist_vcn_end())
		result += fmt.Sprintf("  Runlist_offset: %#0x\n", self.Runlist_offset())
		result += fmt.Sprintf("  Compression_unit_size: %#0x\n", self.Compression_unit_size())
		result += fmt.Sprintf("  Allocated_size: %#0x\n", self.Allocated_size())
		result += fmt.Sprintf("  Actual_size: %#0x\n", self.Actual_size())
		result += fmt.Sprintf("  Initialized_size: %#0x\n", self.Initialized_size())
	}
	return result
}

// MFT_ENTRY with a bit of caching.
type MFT_ENTRY struct {
	Reader  io.ReaderAt
	Offset  int64
	Profile *NTFSProfile
}

func (self *MFT_ENTRY) Size() int {
	return 0
}

func (self *MFT_ENTRY) Magic() *Signature {
	value := ParseSignature(self.Reader, self.Profile.Off_MFT_ENTRY_Magic+self.Offset, 4)
	return &Signature{value: value, signature: "FILE"}
}

func (self *MFT_ENTRY) Fixup_offset() uint16 {
	return ParseUint16(self.Reader, self.Profile.Off_MFT_ENTRY_Fixup_offset+self.Offset)
}

func (self *MFT_ENTRY) Fixup_count() uint16 {
	return ParseUint16(self.Reader, self.Profile.Off_MFT_ENTRY_Fixup_count+self.Offset)
}

func (self *MFT_ENTRY) Logfile_sequence_number() uint64 {
	return ParseUint64(self.Reader, self.Profile.Off_MFT_ENTRY_Logfile_sequence_number+self.Offset)
}

func (self *MFT_ENTRY) Sequence_value() uint16 {
	return ParseUint16(self.Reader, self.Profile.Off_MFT_ENTRY_Sequence_value+self.Offset)
}

func (self *MFT_ENTRY) Link_count() uint16 {
	return ParseUint16(self.Reader, self.Profile.Off_MFT_ENTRY_Link_count+self.Offset)
}

func (self *MFT_ENTRY) Attribute_offset() uint16 {
	return ParseUint16(self.Reader, self.Profile.Off_MFT_ENTRY_Attribute_offset+self.Offset)
}

func (self *MFT_ENTRY) Flags() *Flags {
	value := ParseUint16(self.Reader, self.Profile.Off_MFT_ENTRY_Flags+self.Offset)
	names := make(map[string]bool)

	if value&(1<<0) != 0 {
		names["ALLOCATED"] = true
	}

	if value&(1<<1) != 0 {
		names["DIRECTORY"] = true
	}

	return &Flags{Value: uint64(value), Names: names}
}

func (self *MFT_ENTRY) Mft_entry_size() uint16 {
	return ParseUint16(self.Reader, self.Profile.Off_MFT_ENTRY_Mft_entry_size+self.Offset)
}

func (self *MFT_ENTRY) Mft_entry_allocated() uint16 {
	return ParseUint16(self.Reader, self.Profile.Off_MFT_ENTRY_Mft_entry_allocated+self.Offset)
}

func (self *MFT_ENTRY) Base_record_reference() uint64 {
	return ParseUint64(self.Reader, self.Profile.Off_MFT_ENTRY_Base_record_reference+self.Offset)
}

func (self *MFT_ENTRY) Next_attribute_id() uint16 {
	return ParseUint16(self.Reader, self.Profile.Off_MFT_ENTRY_Next_attribute_id+self.Offset)
}

func (self *MFT_ENTRY) Record_number() uint32 {
	return ParseUint32(self.Reader, self.Profile.Off_MFT_ENTRY_Record_number+self.Offset)
}
func (self *MFT_ENTRY) DebugString() string {
	result := fmt.Sprintf("struct MFT_ENTRY @ %#x:\n", self.Offset)
	result += fmt.Sprintf("  Fixup_offset: %#0x\n", self.Fixup_offset())
	result += fmt.Sprintf("  Fixup_count: %#0x\n", self.Fixup_count())
	result += fmt.Sprintf("  Logfile_sequence_number: %#0x\n", self.Logfile_sequence_number())
	result += fmt.Sprintf("  Sequence_value: %#0x\n", self.Sequence_value())
	result += fmt.Sprintf("  Link_count: %#0x\n", self.Link_count())
	result += fmt.Sprintf("  Attribute_offset: %#0x\n", self.Attribute_offset())
	result += fmt.Sprintf("  Flags: %v\n", self.Flags().DebugString())
	result += fmt.Sprintf("  Mft_entry_size: %#0x\n", self.Mft_entry_size())
	result += fmt.Sprintf("  Mft_entry_allocated: %#0x\n", self.Mft_entry_allocated())
	result += fmt.Sprintf("  Base_record_reference: %#0x\n", self.Base_record_reference())
	result += fmt.Sprintf("  Next_attribute_id: %#0x\n", self.Next_attribute_id())
	result += fmt.Sprintf("  Record_number: %#0x\n", self.Record_number())
	return result
}
