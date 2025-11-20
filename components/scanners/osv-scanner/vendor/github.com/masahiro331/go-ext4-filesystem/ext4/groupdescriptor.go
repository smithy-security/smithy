package ext4

// GroupDescriptor32 is 32 byte
type GroupDescriptor32 struct {
	BlockBitmapLo     uint32 `struc:"uint32,little"`
	InodeBitmapLo     uint32 `struc:"uint32,little"`
	InodeTableLo      uint32 `struc:"uint32,little"`
	FreeBlocksCountLo uint16 `struc:"uint16,little"`
	FreeInodesCountLo uint16 `struc:"uint16,little"`
	UsedDirsCountLo   uint16 `struc:"uint16,little"`
	Flags             uint16 `struc:"uint16,little"`
	ExcludeBitmapLo   uint32 `struc:"uint32,little"`
	BlockBitmapCsumLo uint16 `struc:"uint16,little"`
	InodeBitmapCsumLo uint16 `struc:"uint16,little"`
	ItableUnusedLo    uint16 `struc:"uint16,little"`
	Checksum          uint16 `struc:"uint16,little"`
}

// GroupDescriptor is 64 byte
type GroupDescriptor struct {
	GroupDescriptor32
	BlockBitmapHi     uint32 `struc:"uint32,little"`
	InodeBitmapHi     uint32 `struc:"uint32,little"`
	InodeTableHi      uint32 `struc:"uint32,little"`
	FreeBlocksCountHi uint16 `struc:"uint16,little"`
	FreeInodesCountHi uint16 `struc:"uint16,little"`
	UsedDirsCountHi   uint16 `struc:"uint16,little"`
	ItableUnusedHi    uint16 `struc:"uint16,little"`
	ExcludeBitmapHi   uint32 `struc:"uint32,little"`
	BlockBitmapCsumHi uint16 `struc:"uint16,little"`
	InodeBitmapCsumHi uint16 `struc:"uint16,little"`
	Reserved          uint32 `struc:"uint32,little"`
}

// GetInodeBitmapLoc is ...
func (gd *GroupDescriptor) GetInodeBitmapLoc(featureInCompat64bit bool) int64 {
	if featureInCompat64bit {
		return (int64(gd.InodeBitmapHi) << 32) | int64(gd.InodeBitmapLo)
	}
	return int64(gd.InodeBitmapLo)
}

// GetInodeTableLoc is ...
func (gd *GroupDescriptor) GetInodeTableLoc(featureInCompat64bit bool) int64 {
	if featureInCompat64bit {
		return (int64(gd.InodeTableHi) << 32) | int64(gd.InodeTableLo)
	}
	return int64(gd.InodeTableLo)
}

// GetBlockBitmapLoc is ...
func (gd *GroupDescriptor) GetBlockBitmapLoc(featureInCompat64bit bool) int64 {
	if featureInCompat64bit {
		return (int64(gd.BlockBitmapHi) << 32) | int64(gd.BlockBitmapLo)
	}
	return int64(gd.BlockBitmapLo)
}
