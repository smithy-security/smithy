package parser

import (
	"strings"
	"time"
)

// This file defines a model for MFT entry.

type TimeStamps struct {
	CreateTime       time.Time
	FileModifiedTime time.Time
	MFTModifiedTime  time.Time
	AccessedTime     time.Time
}

type FilenameInfo struct {
	Times                TimeStamps
	Type                 string
	Name                 string
	ParentEntryNumber    uint64
	ParentSequenceNumber uint16
}

type Attribute struct {
	Type     string
	TypeId   uint64
	Id       uint64
	Inode    string
	Size     int64
	Name     string
	Resident bool
}

// Describe a single MFT entry.
type NTFSFileInformation struct {
	FullPath       string
	MFTID          int64
	SequenceNumber uint16
	Size           int64
	Allocated      bool
	IsDir          bool
	SI_Times       *TimeStamps

	// If multiple filenames are given, we list them here.
	Filenames []*FilenameInfo

	Attributes []*Attribute

	Hardlinks []string
}

func ModelMFTEntry(ntfs *NTFSContext, mft_entry *MFT_ENTRY) (*NTFSFileInformation, error) {
	full_path := GetFullPath(ntfs, mft_entry)
	mft_id := mft_entry.Record_number()

	result := &NTFSFileInformation{
		FullPath:       full_path,
		MFTID:          int64(mft_id),
		SequenceNumber: mft_entry.Sequence_value(),
		Allocated:      mft_entry.Flags().IsSet("ALLOCATED"),
		IsDir:          mft_entry.Flags().IsSet("DIRECTORY"),
	}

	si, err := mft_entry.StandardInformation(ntfs)
	if err == nil {
		result.SI_Times = &TimeStamps{
			CreateTime:       si.Create_time().Time,
			FileModifiedTime: si.File_altered_time().Time,
			MFTModifiedTime:  si.Mft_altered_time().Time,
			AccessedTime:     si.File_accessed_time().Time,
		}
	}

	for _, filename := range mft_entry.FileName(ntfs) {
		result.Filenames = append(result.Filenames, &FilenameInfo{
			Times: TimeStamps{
				CreateTime:       filename.Created().Time,
				FileModifiedTime: filename.File_modified().Time,
				MFTModifiedTime:  filename.Mft_modified().Time,
				AccessedTime:     filename.File_accessed().Time,
			},
			ParentEntryNumber:    filename.MftReference(),
			ParentSequenceNumber: filename.Seq_num(),
			Type:                 filename.NameType().Name,
			Name:                 filename.Name(),
		})
	}

	inode_formatter := InodeFormatter{}

	for _, attr := range mft_entry.EnumerateAttributes(ntfs) {
		attr_type := attr.Type()
		attr_id := attr.Attribute_id()

		if attr_type.Value == ATTR_TYPE_DATA && result.Size == 0 {
			result.Size = attr.DataSize()
		}

		// Only show the first VCN - additional VCN are just
		// part of the original stream.
		if !attr.IsResident() && attr.Runlist_vcn_start() != 0 {
			continue
		}

		name := attr.Name()

		result.Attributes = append(result.Attributes, &Attribute{
			Type:     attr_type.Name,
			TypeId:   attr_type.Value,
			Inode:    inode_formatter.Inode(mft_id, attr_type.Value, attr_id, name),
			Size:     attr.DataSize(),
			Id:       uint64(attr_id),
			Name:     name,
			Resident: attr.IsResident(),
		})
	}

	for _, l := range GetHardLinks(ntfs, uint64(mft_id), DefaultMaxLinks) {
		result.Hardlinks = append(result.Hardlinks, strings.Join(l, "\\"))
	}

	return result, nil
}
