package exfat

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/dsoprea/go-logging"
	"github.com/go-restruct/restruct"
)

// EntryType allows us to decompose an EntryType value.
type EntryType uint8

// IsEndOfDirectory indicates that this is the last entry in the directory.
func (et EntryType) IsEndOfDirectory() bool {
	return et == 0
}

// IsUnusedEntryMarker indicates that the directory-entry is a placeholder.
func (et EntryType) IsUnusedEntryMarker() bool {
	return et >= 0x01 && et <= 0x7f
}

// IsRegular indicates that this entry is a normal directory entry and
// unremarkable.
func (et EntryType) IsRegular() bool {
	return et >= 0x81 && et <= 0xff
}

// TypeCode indicates the general type of the entry. This is not unique unless
// combined with the 'importance' flag and 'critical' flag.
func (et EntryType) TypeCode() int {
	return int(et & 31)
}

// TypeImportance indicates whether or not this is a mandatory or options entry-
// type.
func (et EntryType) TypeImportance() bool {
	return et&32 > 0
}

// IsCritical indicates whether 'importance' is cleared (enabled).
func (et EntryType) IsCritical() bool {
	return et.TypeImportance() == false
}

// IsBenign indicates whether 'importance' is set (disabled).
func (et EntryType) IsBenign() bool {
	return et.TypeImportance() == true
}

// TypeCategory indicates whether this is a primary record or a secondary entry
// (which will *accompany* a primary entry).
func (et EntryType) TypeCategory() bool {
	return et&64 > 0
}

// IsPrimary indicates whether 'category' is cleared (enabled).
func (et EntryType) IsPrimary() bool {
	return et.TypeCategory() == false
}

// IsSecondary indicates whether 'category' is set (disabled).
func (et EntryType) IsSecondary() bool {
	return et.TypeCategory() == true
}

// IsInUse indicates that the entry is not unused, i.e. a regular directory-
// entry.
func (et EntryType) IsInUse() bool {
	return et&128 > 0
}

// Dump dumps all flags/states embedded in the entry-type value.
func (et EntryType) Dump() {
	fmt.Printf("Entry Type\n")
	fmt.Printf("==========\n")
	fmt.Printf("\n")

	fmt.Printf("TypeCode: (%d)\n", et.TypeCode())
	fmt.Printf("\n")

	fmt.Printf("TypeImportance: [%v]\n", et.TypeImportance())
	fmt.Printf("- IsCritical: [%v]\n", et.IsCritical())
	fmt.Printf("- IsBenign: [%v]\n", et.IsBenign())
	fmt.Printf("\n")

	fmt.Printf("TypeCategory: [%v]\n", et.TypeCategory())
	fmt.Printf("- IsPrimary: [%v]\n", et.IsPrimary())
	fmt.Printf("- IsSecondary: [%v]\n", et.IsSecondary())
	fmt.Printf("\n")

	fmt.Printf("IsInUse: [%v]\n", et.IsInUse())
	fmt.Printf("\n")

	fmt.Printf("Entry-Type Classes\n")
	fmt.Printf("- IsEndOfDirectory: [%v]\n", et.IsEndOfDirectory())
	fmt.Printf("- IsUnusedEntryMarker: [%v]\n", et.IsUnusedEntryMarker())
	fmt.Printf("- IsRegular: [%v]\n", et.IsRegular())
	fmt.Printf("\n")
}

// String returns a descriptive string.
func (et EntryType) String() string {
	return fmt.Sprintf("EntryType<TYPE-CODE=(%d) IS-CRITICAL=[%v] IS-PRIMARY=[%v] IS-IN-USE=[%v] X-IS-REGULAR=[%v] X-IS-UNUSED=[%v] X-IS-END=[%v]>", et.TypeCode(), et.IsCritical(), et.IsPrimary(), et.IsInUse(), et.IsRegular(), et.IsUnusedEntryMarker(), et.IsEndOfDirectory())
}

// DirectoryEntryParserKey describes the combination of attributes that uniquely
// identify an entry-type (`isCritical` corresponds directly to
// `TypeImportance` and `isPrimary` corresponds directly to `TypeCategory`):
//
//  6.2.1.1 TypeCode Field
//
//  The TypeCode field partially describes the specific type of the given directory entry. This field, plus the TypeImportance and TypeCategory fields (see Sections 6.2.1.2 and 6.2.1.3, respectively) uniquely identify the type of the given directory entry.
type DirectoryEntryParserKey struct {
	typeCode   int
	isCritical bool
	isPrimary  bool
}

// String returns a descriptive string.
func (depk DirectoryEntryParserKey) String() string {
	return fmt.Sprintf("DirectoryEntryParserKey<TYPE-CODE=(%d) IS-CRITICAL=[%v] IS-PRIMARY=[%v]>", depk.typeCode, depk.isCritical, depk.isPrimary)
}

var (
	// directoryEntryParsers expresses all entry-types describes in the exFAT
	// specification (and required *by* the specification).
	directoryEntryParsers = map[DirectoryEntryParserKey]reflect.Type{

		//// Critical primary

		// Allocation Bitmap (Section 7.1)
		{typeCode: 1, isCritical: true, isPrimary: true}: reflect.TypeOf(ExfatAllocationBitmapDirectoryEntry{}),

		// Up-case Table (Section 7.2)
		{typeCode: 2, isCritical: true, isPrimary: true}: reflect.TypeOf(ExfatUpcaseTableDirectoryEntry{}),

		// Volume Label (Section 7.3)
		{typeCode: 3, isCritical: true, isPrimary: true}: reflect.TypeOf(ExfatVolumeLabelDirectoryEntry{}),

		// File (Section 7.4)
		{typeCode: 5, isCritical: true, isPrimary: true}: reflect.TypeOf(ExfatFileDirectoryEntry{}),

		//// Benign primary

		// Volume GUID (Section 7.5)
		{typeCode: 0, isCritical: false, isPrimary: true}: reflect.TypeOf(ExfatVolumeGuidDirectoryEntry{}),

		// TexFAT Padding (Section 7.10)
		{typeCode: 1, isCritical: false, isPrimary: true}: reflect.TypeOf(ExfatTexFATDirectoryEntry{}),

		//// Critical secondary

		// Stream Extension (Section 7.6)
		{typeCode: 0, isCritical: true, isPrimary: false}: reflect.TypeOf(ExfatStreamExtensionDirectoryEntry{}),

		// File Name (Section 7.7)
		{typeCode: 1, isCritical: true, isPrimary: false}: reflect.TypeOf(ExfatFileNameDirectoryEntry{}),

		//// Benign secondary

		// Vendor Extension (Section 7.8)
		{typeCode: 0, isCritical: false, isPrimary: false}: reflect.TypeOf(ExfatVendorExtensionDirectoryEntry{}),

		// Vendor Allocation (Section 7.9)
		{typeCode: 1, isCritical: false, isPrimary: false}: reflect.TypeOf(ExfatVendorAllocationDirectoryEntry{}),
	}
)

// DirectoryEntry represents any of the directory-entry structs defined here.
type DirectoryEntry interface {
	TypeName() string
}

// PrimaryDirectoryEntry represents the common methods found on any primary-
// type DE, which is really just SecondaryCount().
type PrimaryDirectoryEntry interface {
	SecondaryCount() uint8
}

// DumpableDirectoryEntry represents any directory-entry that can dump its
// information to the screen. This is really just DEs that we've taken the time
// to do this for that also contain a wealth of information.
type DumpableDirectoryEntry interface {
	Dump()
}

// ExfatTimestamp is the raw packaged integer with timestamp information. It
// embeds its parsing semantics.
type ExfatTimestamp uint32

// Second returns the second component.
func (et ExfatTimestamp) Second() int {
	return int(et & 31)
}

// Minute returns the minute component.
func (et ExfatTimestamp) Minute() int {
	return int(et&2016) >> 5
}

// Hour returns the hour component.
func (et ExfatTimestamp) Hour() int {
	return int(et&63488) >> 11
}

// Day returns the day component.
func (et ExfatTimestamp) Day() int {
	return int(et&2031616) >> 16
}

// Month returns the minute component.
func (et ExfatTimestamp) Month() int {
	return int(et&31457280) >> 21
}

// Year returns the year component.
func (et ExfatTimestamp) Year() int {
	return 1980 + int(et&4261412864)>>25
}

// TimestampWithOffset returns a location-corrected timestamp.
func (et ExfatTimestamp) TimestampWithOffset(offset int) time.Time {
	location := time.FixedZone(fmt.Sprintf("(off=%d)", offset), offset)

	return time.Date(et.Year(), time.Month(et.Month()), et.Day(), et.Hour(), et.Minute(), et.Second(), 0, location)
}

// FileAttributes allows us to decompose the attributes integer into the various
// attributes that a file/directory can have.
type FileAttributes uint16

// IsReadOnly returns whether the file should be read-only.
func (fa FileAttributes) IsReadOnly() bool {
	return fa&1 > 0
}

// IsHidden returns whether the file should not be present in standard file
// listings by default.
func (fa FileAttributes) IsHidden() bool {
	return fa&2 > 0
}

// IsSystem returns the system flag.
func (fa FileAttributes) IsSystem() bool {
	return fa&4 > 0
}

// IsDirectory returns whether this entry is a directory.
func (fa FileAttributes) IsDirectory() bool {
	return fa&16 > 0
}

// IsArchive returns whether the archive flag has been set on the current file.
func (fa FileAttributes) IsArchive() bool {
	return fa&32 > 0
}

// String returns a descriptive string.
func (fa FileAttributes) String() string {
	return fmt.Sprintf("FileAttributes<IS-READONLY=[%v] IS-HIDDEN=[%v] IS-SYSTEM=[%v] IS-DIRECTORY=[%v] IS-ARCHIVE=[%v]>",
		fa.IsReadOnly(), fa.IsHidden(), fa.IsSystem(), fa.IsDirectory(), fa.IsArchive())
}

// DumpBareIndented prints the various attribute states preceding by arbitrary
// indentation.
func (fa FileAttributes) DumpBareIndented(indent string) {
	fmt.Printf("%sRead Only? [%v]\n", indent, fa.IsReadOnly())
	fmt.Printf("%sHidden? [%v]\n", indent, fa.IsHidden())
	fmt.Printf("%sSystem? [%v]\n", indent, fa.IsSystem())
	fmt.Printf("%sDirectory? [%v]\n", indent, fa.IsDirectory())
	fmt.Printf("%sArchive? [%v]\n", indent, fa.IsArchive())
}

// ExfatFileDirectoryEntry describes file entries.
type ExfatFileDirectoryEntry struct {
	// EntryType: This field is mandatory and Section 7.4.1 defines its contents.
	EntryType EntryType

	// SecondaryCount: This field is mandatory and Section 7.4.2 defines its contents.
	SecondaryCountRaw uint8

	// SetChecksum: This field is mandatory and Section 7.4.3 defines its contents.
	SetChecksum uint16

	// FileAttributes: This field is mandatory and Section 7.4.4 defines its contents.
	FileAttributes FileAttributes

	// Reserved1: This field is mandatory and its contents are reserved.
	Reserved1 uint16

	// CreateTimestampRaw: This field is mandatory and Section 7.4.5 defines its contents.
	CreateTimestampRaw ExfatTimestamp

	// LastModifiedTimestampRaw: This field is mandatory and Section 7.4.6 defines its contents.
	LastModifiedTimestampRaw ExfatTimestamp

	// LastAccessedTimestampRaw: This field is mandatory and Section 7.4.7 defines its contents.
	LastAccessedTimestampRaw ExfatTimestamp

	// Create10msIncrement: This field is mandatory and Section 7.4.5 defines its contents.
	Create10msIncrement uint8

	// LastModified10msIncrement: This field is mandatory and Section 7.4.6 defines its contents.
	LastModified10msIncrement uint8

	// CreateUtcOffset: This field is mandatory and Section 7.4.5 defines its contents.
	CreateUtcOffset uint8

	// LastModifiedUtcOffset: This field is mandatory and Section 7.4.6 defines its contents.
	LastModifiedUtcOffset uint8

	// LastAccessedUtcOffset: This field is mandatory and Section 7.4.7 defines its contents.
	LastAccessedUtcOffset uint8

	// Reserved2: This field is mandatory and its contents are reserved.
	Reserved2 [7]byte
}

// String returns a descriptive string.
func (fdf ExfatFileDirectoryEntry) String() string {
	return fmt.Sprintf("FileDirectoryEntry<SECONDARY-COUNT=(%d) CTIME=[%s] MTIME=[%s] ATIME=[%s]>",
		fdf.SecondaryCountRaw,
		fdf.CreateTimestamp(), fdf.LastModifiedTimestamp(), fdf.LastAccessedTimestamp())
}

// SecondaryCount indicates how many of the subsequent secondary entries should
// be collected to support this entry.
func (fdf ExfatFileDirectoryEntry) SecondaryCount() uint8 {
	return fdf.SecondaryCountRaw
}

// TypeName returns a unique name for this entry-type.
func (fdf ExfatFileDirectoryEntry) TypeName() string {
	return "File"
}

// CreateTimestamp returns the offset-corrected ctime.
func (fdf ExfatFileDirectoryEntry) CreateTimestamp() time.Time {
	return fdf.CreateTimestampRaw.TimestampWithOffset(int(fdf.CreateUtcOffset))
}

// LastModifiedTimestamp returns the offset-corrected mtime.
func (fdf ExfatFileDirectoryEntry) LastModifiedTimestamp() time.Time {
	return fdf.LastModifiedTimestampRaw.TimestampWithOffset(int(fdf.LastModifiedUtcOffset))
}

// LastAccessedTimestamp returns the offset-corrected atime.
func (fdf ExfatFileDirectoryEntry) LastAccessedTimestamp() time.Time {
	return fdf.LastAccessedTimestampRaw.TimestampWithOffset(int(fdf.LastAccessedUtcOffset))
}

// Dump prints the file entry's info to STDOUT.
func (fdf ExfatFileDirectoryEntry) Dump() {
	fmt.Printf("File Directory Entry\n")
	fmt.Printf("====================\n")
	fmt.Printf("\n")

	fmt.Printf("SecondaryCount: (%d)\n", fdf.SecondaryCount())
	fmt.Printf("SetChecksum: (0x%04x)\n", fdf.SetChecksum)
	fmt.Printf("CreateTimestamp: [%s]\n", fdf.CreateTimestamp())
	fmt.Printf("LastModifiedTimestamp: [%s]\n", fdf.LastModifiedTimestamp())
	fmt.Printf("LastAccessedTimestamp: [%s]\n", fdf.LastAccessedTimestamp())
	fmt.Printf("\n")

	fmt.Printf("Attributes:\n")

	fdf.FileAttributes.DumpBareIndented("  ")

	fmt.Printf("\n")
}

// ExfatAllocationBitmapDirectoryEntry points to the cluster that has the
// allocation bitmap.
type ExfatAllocationBitmapDirectoryEntry struct {
	// EntryType: This field is mandatory and Section 7.1.1 defines its contents.
	EntryType EntryType

	// BitmapFlags: This field is mandatory and Section 7.1.2 defines its contents.
	BitmapFlags uint8

	// Reserved: This field is mandatory and its contents are reserved.
	Reserved [18]byte

	// FirstCluster: This field is mandatory and Section 7.1.3 defines its contents.
	FirstCluster uint32

	// DataLength: This field is mandatory and Section 7.1.4 defines its contents.
	DataLength uint64
}

// String returns a string description.
func (abde ExfatAllocationBitmapDirectoryEntry) String() string {
	return fmt.Sprintf("AllocationBitmapDirectoryEntry<BITMAP-FLAGS=[%08b] FIRST-CLUSTER=(%d) DATA-LENGTH=(%d)>", abde.BitmapFlags, abde.FirstCluster, abde.DataLength)
}

// TypeName returns a unique name for this entry-type.
func (ExfatAllocationBitmapDirectoryEntry) TypeName() string {
	return "AllocationBitmap"
}

// ExfatUpcaseTableDirectoryEntry points to the cluster that provides the
// mapping for various characters back to the original characters in order
// to support case-insensitivity.
type ExfatUpcaseTableDirectoryEntry struct {
	// EntryType: This field is mandatory and Section 7.2.1 defines its contents.
	EntryType EntryType

	// Reserved1: This field is mandatory and its contents are reserved.
	Reserved1 [3]byte

	// TableChecksum: This field is mandatory and Section 7.2.2 defines its contents.
	TableChecksum uint32

	// Reserved2: This field is mandatory and its contents are reserved.
	Reserved2 [12]byte

	// FirstCluster: This field is mandatory and Section 7.2.3 defines its contents.
	FirstCluster uint32

	// DataLength: This field is mandatory and Section 7.2.4 defines its contents.
	DataLength uint64
}

// String returns a string description.
func (utde ExfatUpcaseTableDirectoryEntry) String() string {
	return fmt.Sprintf("UpcaseTableDirectoryEntry<TABLE-CHECKSUM=[0x%08x] FIRST-CLUSTER=(%d) DATA-LENGTH=(%d)>", utde.TableChecksum, utde.FirstCluster, utde.DataLength)
}

// TypeName returns a unique name for this entry-type.
func (ExfatUpcaseTableDirectoryEntry) TypeName() string {
	return "UpcaseTable"
}

// ExfatVolumeLabelDirectoryEntry embeds the volume label.
type ExfatVolumeLabelDirectoryEntry struct {
	// EntryType: This field is mandatory and Section 7.3.1 defines its contents.
	EntryType EntryType

	// CharacterCount: This field is mandatory and Section 7.3.2 defines its contents.
	CharacterCount uint8

	// VolumeLabel: This field is mandatory and Section 7.3.3 defines its contents.
	//
	// NOTES
	//
	// - The specification states that this is Unicode (naturally):
	//
	//      The VolumeLabel field shall contain a Unicode string, which is the
	//      user-friendly name of the volume. The VolumeLabel field has the same
	//      set of invalid characters as the FileName field of the File Name
	//      directory entry (see Section 7.7.3).
	//
	// - In practice, tools will combine both the `VolumeLabel` and `Reserved`
	//   fields. So, we combine them here.
	VolumeLabel [30]byte

	// // VolumeLabel: This field is mandatory and Section 7.3.3 defines its contents.
	// VolumeLabel [22]byte

	// // Reserved: This field is mandatory and its contents are reserved.
	// Reserved [8]byte
}

// Label constructs and returns the final Unicode string.
func (vlde ExfatVolumeLabelDirectoryEntry) Label() string {
	// `VolumeLabel` is a Unicode-encoded string and the character-count
	// corresponds to the number of Unicode characters.

	decodedString := UnicodeFromAscii(vlde.VolumeLabel[:], int(vlde.CharacterCount))
	return decodedString
}

// String returns a string description.
func (vlde ExfatVolumeLabelDirectoryEntry) String() string {
	return fmt.Sprintf("VolumeLabelDirectoryEntry<CHARACTER-COUNT=(%d) LABEL=[%s]>", vlde.CharacterCount, vlde.Label())
}

// TypeName returns a unique name for this entry-type.
func (ExfatVolumeLabelDirectoryEntry) TypeName() string {
	return "VolumeLabel"
}

// ExfatVolumeGuidDirectoryEntry embeds the volume GUID.
type ExfatVolumeGuidDirectoryEntry struct {
	// EntryType: This field is mandatory and Section 7.5.1 defines its contents.
	EntryType EntryType

	// SecondaryCount: This field is mandatory and Section 7.5.2 defines its contents.
	SecondaryCountRaw uint8

	// SetChecksum: This field is mandatory and Section 7.5.3 defines its contents.
	SetChecksum uint16

	// GeneralPrimaryFlags: This field is mandatory and Section 7.5.4 defines its contents.
	GeneralPrimaryFlags uint16

	// VolumeGuid: This field is mandatory and Section 7.5.5 defines its contents.
	VolumeGuid [16]byte

	// Reserved: This field is mandatory and its contents are reserved.
	Reserved [10]byte
}

// String returns a descriptive string.
func (vgde ExfatVolumeGuidDirectoryEntry) String() string {
	return fmt.Sprintf("VolumeGuidDirectoryEntry<SECONDARY-COUNT=(%d) SET-CHECKSUM=(0x%04x) GENERAL-PRIMARY-FLAGS=(0x%04x) GUID=[0x%016x...]>", vgde.SecondaryCountRaw, vgde.SetChecksum, vgde.GeneralPrimaryFlags, vgde.VolumeGuid[:4])
}

// SecondaryCount returns the count of associated secondary-records.
func (vgde ExfatVolumeGuidDirectoryEntry) SecondaryCount() uint8 {
	return vgde.SecondaryCountRaw
}

// TypeName returns a unique name for this entry-type.
func (ExfatVolumeGuidDirectoryEntry) TypeName() string {
	return "VolumeGuid"
}

// ExfatTexFATDirectoryEntry is a mobile-device entry-type that is not defined
// by exFAT.
type ExfatTexFATDirectoryEntry struct {
	// Reserved: Not covered by the exFAT specification. Just mask the whole thing as reserved.
	Reserved [32]byte
}

// String returns a descriptive string.
func (ExfatTexFATDirectoryEntry) String() string {
	return "TexFATDirectoryEntry<>"
}

// TypeName returns a unique name for this entry-type.
func (ExfatTexFATDirectoryEntry) TypeName() string {
	return "TexFAT"
}

// GeneralSecondaryFlags allows us to decompose the flags frequently embedded in
// secondary directory entries.
type GeneralSecondaryFlags uint8

// IsAllocationPossible indicates that writes are supported for this entry-type.
func (gsf GeneralSecondaryFlags) IsAllocationPossible() bool {
	return gsf&1 > 0
}

// NoFatChain whether the data is stored sequentially on disk or the FAT is
// required to find the subsequent ones.
func (gsf GeneralSecondaryFlags) NoFatChain() bool {
	return gsf&2 > 0
}

// String returns a descriptive string.
func (gsf GeneralSecondaryFlags) String() string {
	return fmt.Sprintf("GeneralSecondaryFlags<IsAllocationPossible=[%v] NoFatChain=[%v]>",
		gsf.IsAllocationPossible(), gsf.NoFatChain())
}

// DumpBareIndented prints the secondary-flags with arbitrary indentation.
func (gsf GeneralSecondaryFlags) DumpBareIndented(indent string) {
	fmt.Printf("%sRaw Value: (%08b)\n", indent, gsf)
	fmt.Printf("%sIsAllocationPossible: [%v]\n", indent, gsf.IsAllocationPossible())
	fmt.Printf("%sNoFatChain: [%v]\n", indent, gsf.NoFatChain())
}

// ExfatStreamExtensionDirectoryEntry describes the actual contents of a file.
type ExfatStreamExtensionDirectoryEntry struct {

	// TODO(dustin): It's unclear where the names for the one or more streams under each file are stored.

	// EntryType: This field is mandatory and Section 7.6.1 defines its contents.
	EntryType EntryType

	// GeneralSecondaryFlags: This field is mandatory and Section 7.6.2 defines its contents.
	GeneralSecondaryFlags GeneralSecondaryFlags

	// Reserved1: This field is mandatory and its contents are reserved.
	Reserved1 [1]byte

	// NameLength: This field is mandatory and Section 7.6.3 defines its contents.
	NameLength uint8

	// NameHash: This field is mandatory and Section 7.6.4 defines its contents.
	NameHash uint16

	// Reserved2: This field is mandatory and its contents are reserved.
	Reserved2 [2]byte

	// ValidDataLength: This field is mandatory and Section 7.6.5 defines its contents.
	//
	// NOTES
	//
	// - For files, `ValidDataLength` is the real amount of data. Ostensibly,
	//   subsequent updates to a file don't necessarily have to occupy as much
	//   space as is already allocated and this describes the actual data size.
	//   For directories, only `DataLength` should be considered.
	//
	//   From the spec (7.6.5 ValidDataLength Field):
	//
	//      The ValidDataLength field shall describe how far into the data
	//      stream user data has been written. Implementations shall update this
	//      field as they write data further out into the data stream. On the
	//      storage media, the data between the valid data length and the data
	//      length of the data stream is undefined. Implementations shall return
	//      zeroes for read operations beyond the valid data length.
	//
	//      If the corresponding File directory entry describes a directory,
	//      then the only valid value for this field is equal to the value of
	//      the DataLength field.
	//
	ValidDataLength uint64

	// Reserved3: This field is mandatory and its contents are reserved.
	Reserved3 [4]byte

	// FirstCluster: This field is mandatory and Section 7.6.6 defines its contents.
	//
	// NOTES
	//
	// - If a directory, this cluster has all of the subdirectories and files
	//   for that directory (formatted the same as the root directory located at
	//   cluster FirstClusterOfRootDirectory).
	//
	FirstCluster uint32

	// DataLength: This field is mandatory and Section 7.6.7 defines its contents.
	DataLength uint64
}

// String returns a descriptive string.
func (sede ExfatStreamExtensionDirectoryEntry) String() string {
	return fmt.Sprintf("StreamExtensionDirectoryEntry<GENERAL-SECONDARY-FLAGS=(%08b) NAME-LENGTH=(%d) NAME-HASH=(0x%04x) VALID-DATA-LENGTH=(%d) FIRST-CLUSTER=(%d) DATA-LENGTH=(%d)>",
		sede.GeneralSecondaryFlags, sede.NameLength, sede.NameHash, sede.ValidDataLength, sede.FirstCluster, sede.DataLength)
}

// Dump prints the stream entry's info to STDOUT.
func (sede ExfatStreamExtensionDirectoryEntry) Dump() {
	fmt.Printf("Stream Extension Directory Entry\n")
	fmt.Printf("================================\n")
	fmt.Printf("\n")

	fmt.Printf("NameLength: (%d)\n", sede.NameLength)
	fmt.Printf("NameHash: (0x%04x)\n", sede.NameHash)
	fmt.Printf("ValidDataLength: (%d)\n", sede.ValidDataLength)
	fmt.Printf("FirstCluster: (%d)\n", sede.FirstCluster)
	fmt.Printf("DataLength: (%d)\n", sede.DataLength)
	fmt.Printf("\n")

	fmt.Printf("General secondary flags:\n")
	sede.GeneralSecondaryFlags.DumpBareIndented("  ")

	fmt.Printf("\n")
}

// TypeName returns a unique name for this entry-type.
func (ExfatStreamExtensionDirectoryEntry) TypeName() string {
	return "StreamExtension"
}

// ExfatFileNameDirectoryEntry describes one part of the file's complete
// filename.
type ExfatFileNameDirectoryEntry struct {
	// EntryType: This field is mandatory and Section 7.7.1 defines its contents.
	EntryType EntryType

	// GeneralSecondaryFlags: This field is mandatory and Section 7.7.2 defines its contents.
	GeneralSecondaryFlags GeneralSecondaryFlags

	// FileName: This field is mandatory and Section 7.7.3 defines its contents.
	FileName [30]byte
}

// String returns a descriptive string.
func (fnde ExfatFileNameDirectoryEntry) String() string {
	return fmt.Sprintf("FileNameDirectoryEntry<GENERAL-SECONDARY-FLAGS=(%08b) FILENAME=%v>", fnde.GeneralSecondaryFlags, fnde.FileName[:])
}

// TypeName returns a unique name for this entry-type.
func (ExfatFileNameDirectoryEntry) TypeName() string {
	return "FileName"
}

// MultipartFilename describes a set of filename components that need to be
// combined in order to reconstitute the original
type MultipartFilename []DirectoryEntry

// Filename returns the reconstituted filename.
func (mf MultipartFilename) Filename() string {

	// NOTE(dustin): The total filename length is specified in the "Stream
	// Extension" directory entry that occurs after the primary file entry and
	// before these file-name directory-entries, but we don't implement/
	// validate that count, here.

	parts := make([]string, 0)

	for _, deRaw := range mf {
		if fnde, ok := deRaw.(*ExfatFileNameDirectoryEntry); ok == true {
			part := UnicodeFromAscii(fnde.FileName[:], 15)
			parts = append(parts, part)
		}
	}

	filename := strings.Join(parts, "")

	return filename
}

// ExfatVendorExtensionDirectoryEntry describes arbitrary vendor information.
type ExfatVendorExtensionDirectoryEntry struct {
	// EntryType: This field is mandatory and Section 7.8.1 defines its contents.
	EntryType EntryType

	// GeneralSecondaryFlags: This field is mandatory and Section 7.8.2 defines its contents.
	GeneralSecondaryFlags GeneralSecondaryFlags

	// VendorGuid: This field is mandatory and Section 7.8.3 defines its contents.
	VendorGuid [16]byte

	// VendorDefined: This field is mandatory and vendors may define its contents.
	VendorDefined [14]byte
}

// String returns a descriptive string.
func (vede ExfatVendorExtensionDirectoryEntry) String() string {
	return fmt.Sprintf("VendorExtensionDirectoryEntry<GENERAL-SECONDARY-FLAGS=(%08b) GUID=(0x%032x)>", vede.GeneralSecondaryFlags, vede.VendorGuid)
}

// TypeName returns a unique name for this entry-type.
func (ExfatVendorExtensionDirectoryEntry) TypeName() string {
	return "VendorExtension"
}

// ExfatVendorAllocationDirectoryEntry points to a cluster with arbitrary vendor
// information.
type ExfatVendorAllocationDirectoryEntry struct {
	// EntryType: This field is mandatory and Section 7.9.1 defines its contents.
	EntryType EntryType

	// GeneralSecondaryFlags: This field is mandatory and Section 7.9.2 defines its contents.
	GeneralSecondaryFlags GeneralSecondaryFlags

	// VendorGuid: This field is mandatory and Section 7.9.3 defines its contents.
	VendorGuid [16]byte

	// VendorDefined: This field is mandatory and vendors may define its contents.
	VendorDefined [2]byte

	// FirstCluster: This field is mandatory and Section 7.9.4 defines its contents.
	FirstCluster uint32

	// DataLength: This field is mandatory and Section 7.9.5 defines its contents.
	DataLength uint64
}

// String returns a descriptive string.
func (vade ExfatVendorAllocationDirectoryEntry) String() string {
	return fmt.Sprintf("VendorAllocationDirectoryEntry<GENERAL-SECONDARY-FLAGS=(%08b) GUID=(0x%032x) VENDOR-DEFINED=(0x%08x) FIRST-CLUSTER=(%d) DATA-LENGTH=(%d)>", vade.GeneralSecondaryFlags, vade.VendorGuid, vade.VendorDefined, vade.FirstCluster, vade.DataLength)
}

// TypeName returns a unique name for this entry-type.
func (ExfatVendorAllocationDirectoryEntry) TypeName() string {
	return "VendorAllocation"
}

func parseDirectoryEntry(entryType EntryType, directoryEntryData []byte) (parsed DirectoryEntry, err error) {
	defer func() {
		if errRaw := recover(); errRaw != nil {
			err = log.Wrap(errRaw.(error))
		}
	}()

	depk := DirectoryEntryParserKey{
		typeCode:   entryType.TypeCode(),
		isCritical: entryType.IsCritical(),
		isPrimary:  entryType.IsPrimary(),
	}

	structType, found := directoryEntryParsers[depk]
	if found == false {
		log.Panicf("no struct-type recorded for entry-type: %s", depk)
	}

	s := reflect.New(structType)
	x := s.Interface()

	err = restruct.Unpack(directoryEntryData, defaultEncoding, x)
	log.PanicIf(err)

	return x.(DirectoryEntry), nil
}
