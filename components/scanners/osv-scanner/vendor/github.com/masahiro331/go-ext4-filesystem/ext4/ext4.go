package ext4

import (
	"bytes"
	"encoding/binary"
	"io"
	"sort"

	"golang.org/x/xerrors"

	"github.com/masahiro331/go-ext4-filesystem/log"
)

/*
Ext4 Block Layout
+-----------------+------------------+-------------------+---------------------+-------------------+--------------+-------------+------------------+
| Group 0 Padding | ext4 Super Block | Group Descriptors | Reserved GDT Blocks | Data Block Bitmap | inode Bitmap | inode Table	| Data Blocks      |
+-----------------+------------------+-------------------+---------------------+-------------------+--------------+-------------+------------------+
| 1024 bytes      | 1 block	         | many blocks       | many blocks         | 1 block           | 1 block      | many blocks | many more blocks |
+-----------------+------------------+-------------------+---------------------+-------------------+--------------+-------------+------------------+
*/

var (
	ErrInodeNotFound = xerrors.New("inode not found")
)

func Check(r io.Reader) bool {
	_, err := parseSuperBlock(r)
	if err != nil {
		return false
	}
	return true
}

func (ext4 *FileSystem) Extents(inode *Inode) ([]Extent, error) {
	extents, err := ext4.extents(inode.BlockOrExtents[:], nil)
	if err != nil {
		return nil, xerrors.Errorf("failed to get extents: %w", err)
	}
	return extents, nil
}

func (sb Superblock) getGroupDescriptor(r io.SectionReader) ([]GroupDescriptor, error) {
	_, err := r.Seek(sb.GetBlockSize(), 0)
	if err != nil {
		return nil, xerrors.Errorf("failed to seek Group Descriptor offset: %w", err)
	}

	GroupDescriptorSize := int(sb.GetGroupDescriptorTableCount()) * 32
	if sb.FeatureInCompat64bit() {
		GroupDescriptorSize = int(sb.GetGroupDescriptorTableCount()) * 64
	}

	count := divWithRoundUp(GroupDescriptorSize, SectorSize)
	if err != nil {
		return nil, xerrors.Errorf("failed to div: %w", err)
	}
	buf, err := readBlock(&r, int64(count)*SectorSize)
	if err != nil {
		return nil, xerrors.Errorf("failed to read group descriptor: %w", err)
	}
	var gds []GroupDescriptor
	for i := uint32(0); i < sb.GetGroupDescriptorTableCount(); i++ {
		var gd GroupDescriptor
		if sb.FeatureInCompat64bit() {
			err = binary.Read(buf, binary.LittleEndian, &gd)
			if err != nil {
				return nil, xerrors.Errorf("failed to parse 64 bit group descriptor: %w", err)
			}
		} else {
			err = binary.Read(buf, binary.LittleEndian, &gd.GroupDescriptor32)
			if err != nil {
				return nil, xerrors.Errorf("failed to parse 32 bit group descriptor: %w", err)
			}
		}
		gds = append(gds, gd)
	}

	return gds, nil
}

func (ext4 *FileSystem) getInode(inodeAddress int64) (*Inode, error) {
	c, ok := ext4.cache.Get(inodeCacheKey(inodeAddress))
	if ok {
		i := c.(Inode)
		if ok {
			return &i, nil
		}
	}

	bgdIndex := (inodeAddress - 1) / int64(ext4.sb.InodePerGroup)
	if bgdIndex >= int64(len(ext4.gds)) {
		log.Logger.Debugf("inodeAddress: %d, InodePerGroup: %d, bgdIndex: %d", inodeAddress, ext4.sb.InodePerGroup, bgdIndex)
		return nil, xerrors.Errorf("failed to get inode: bgdIndex is out of range bgdIndex: %d len(ext4.gds): %d", bgdIndex, len(ext4.gds))
	}
	bgd := ext4.gds[bgdIndex]
	index := (inodeAddress - 1) % int64(ext4.sb.InodePerGroup)
	physicalOffset := bgd.GetInodeTableLoc(ext4.sb.FeatureInCompat64bit())*ext4.sb.GetBlockSize() + index*int64(ext4.sb.InodeSize)

	// offset need to 512*N offset
	inodeOffset := physicalOffset % SectorSize
	seekOffset := physicalOffset - (physicalOffset % SectorSize)
	buf := make([]byte, SectorSize)
	_, err := ext4.r.ReadAt(buf, seekOffset)
	if err != nil {
		return nil, xerrors.Errorf("failed to read inode: %w", err)
	}
	if inodeOffset != 0 && int64(len(buf)) > inodeOffset {
		buf = buf[inodeOffset:]
	}

	inode := Inode{}
	if err := binary.Read(bytes.NewReader(buf), binary.LittleEndian, &inode); err != nil {
		return nil, xerrors.Errorf("failed to read binary: %w", err)
	}

	ext4.cache.Add(inodeCacheKey(inodeAddress), inode)
	return &inode, nil
}

func (ext4 *FileSystem) extents(b []byte, extents []Extent) ([]Extent, error) {
	extentReader := bytes.NewReader(b)
	extentHeader := &ExtentHeader{}
	err := binary.Read(extentReader, binary.LittleEndian, extentHeader)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse extent header: %w", err)
	}

	if extentHeader.Depth == 0 {
		for entry := uint16(0); entry < extentHeader.Entries; entry++ {
			var extent Extent
			err := binary.Read(extentReader, binary.LittleEndian, &extent)
			if err != nil {
				return nil, xerrors.Errorf("failed to read leaf node extent: %w", err)
			}
			extents = append(extents, extent)
		}
	} else {
		for i := uint16(0); i < extentHeader.Entries; i++ {
			var extent ExtentInternal
			err := binary.Read(extentReader, binary.LittleEndian, &extent)
			if err != nil {
				return nil, xerrors.Errorf("failed to read internal extent: %w", err)
			}
			b := make([]byte, SectorSize)
			_, err = ext4.r.ReadAt(b, int64(extent.LeafHigh)<<32+int64(extent.LeafLow)*ext4.sb.GetBlockSize())
			if err != nil {
				return nil, xerrors.Errorf("failed to read leaf node extent: %w", err)
			}

			extents, err = ext4.extents(b, extents)
			if err != nil {
				return nil, xerrors.Errorf("failed to get extents: %w", err)
			}
		}
	}
	sort.Slice(extents, func(i, j int) bool {
		return extents[i].Block < extents[j].Block
	})
	return extents, nil
}

func (e *Extent) offset() int64 {
	return int64(e.StartHi)<<32 + int64(e.StartLo)
}

func divWithRoundUp(a int, b int) int {
	n := a / b
	if a%b != 0 {
		return n + 1
	}
	return n
}

func readBlock(r io.Reader, size int64) (*bytes.Buffer, error) {
	buf := bytes.NewBuffer(nil)
	for i := int64(0); i < size/SectorSize; i++ {
		n, err := io.CopyN(buf, r, SectorSize)
		if err != nil {
			return nil, xerrors.Errorf("failed to read block: %w", err)
		}
		if n != SectorSize {
			return nil, xerrors.New("failed to read sector")
		}
	}
	return buf, nil
}
