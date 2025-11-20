package ext4

// Superblock is ref https://ext4.wiki.kernel.org/index.php/Ext4_Disk_Layout

type Superblock struct {
	InodeCount           uint32     `struc:"uint32,little"`
	BlockCountLo         uint32     `struc:"uint32,little"`
	RBlockCountLo        uint32     `struc:"uint32,little"`
	FreeBlockCountLo     uint32     `struc:"uint32,little"`
	FreeInodeCount       uint32     `struc:"uint32,little"`
	FirstDataBlock       uint32     `struc:"uint32,little"`
	LogBlockSize         uint32     `struc:"uint32,little"`
	LogClusterSize       uint32     `struc:"uint32,little"`
	BlockPerGroup        uint32     `struc:"uint32,little"`
	ClusterPerGroup      uint32     `struc:"uint32,little"`
	InodePerGroup        uint32     `struc:"uint32,little"`
	Mtime                uint32     `struc:"uint32,little"`
	Wtime                uint32     `struc:"uint32,little"`
	MntCount             uint16     `struc:"uint16,little"`
	MaxMntCount          uint16     `struc:"uint16,little"`
	Magic                uint16     `struc:"uint16,little"`
	State                uint16     `struc:"uint16,little"`
	Errors               uint16     `struc:"uint16,little"`
	MinorRevLevel        uint16     `struc:"uint16,little"`
	Lastcheck            uint32     `struc:"uint32,little"`
	Checkinterval        uint32     `struc:"uint32,little"`
	CreatorOs            uint32     `struc:"uint32,little"`
	RevLevel             uint32     `struc:"uint32,little"`
	DefResuid            uint16     `struc:"uint16,little"`
	DefResgid            uint16     `struc:"uint16,little"`
	FirstIno             uint32     `struc:"uint32,little"`
	InodeSize            uint16     `struc:"uint16,little"`
	BlockGroupNr         uint16     `struc:"uint16,little"`
	FeatureCompat        uint32     `struc:"uint32,little"`
	FeatureIncompat      uint32     `struc:"uint32,little"`
	FeatureRoCompat      uint32     `struc:"uint32,little"`
	UUID                 [16]byte   `struc:"[16]byte"`
	VolumeName           [16]byte   `struc:"[16]byte"`
	LastMounted          [64]byte   `struc:"[64]byte"`
	AlgorithmUsageBitmap uint32     `struc:"uint32,little"`
	PreallocBlocks       byte       `struc:"byte"`
	PreallocDirBlocks    byte       `struc:"byte"`
	ReservedGdtBlocks    uint16     `struc:"uint16,little"`
	JournalUUID          [16]byte   `struc:"[16]byte"`
	JournalInum          uint32     `struc:"uint32,little"`
	JournalDev           uint32     `struc:"uint32,little"`
	LastOrphan           uint32     `struc:"uint32,little"`
	HashSeed             [4]uint32  `struc:"[4]uint32,little"`
	DefHashVersion       byte       `struc:"byte"`
	JnlBackupType        byte       `struc:"byte"`
	DescSize             uint16     `struc:"uint16,little"`
	DefaultMountOpts     uint32     `struc:"uint32,little"`
	FirstMetaBg          uint32     `struc:"uint32,little"`
	MkfTime              uint32     `struc:"uint32,little"`
	JnlBlocks            [17]uint32 `struc:"[17]uint32,little"`
	BlockCountHi         uint32     `struc:"uint32,little"`
	RBlockCountHi        uint32     `struc:"uint32,little"`
	FreeBlockCountHi     uint32     `struc:"uint32,little"`
	MinExtraIsize        uint16     `struc:"uint16,little"`
	WantExtraIsize       uint16     `struc:"uint16,little"`
	Flags                uint32     `struc:"uint32,little"`
	RaidStride           uint16     `struc:"uint16,little"`
	MmpUpdateInterval    uint16     `struc:"uint16,little"`
	MmpBlock             uint64     `struc:"uint64,little"`
	RaidStripeWidth      uint32     `struc:"uint32,little"`
	LogGroupPerFlex      byte       `struc:"byte"`
	ChecksumType         byte       `struc:"byte"`
	EncryptionLevel      byte       `struc:"byte"`
	ReservedPad          byte       `struc:"byte"`
	KbyteWritten         uint64     `struc:"uint64,little"`
	SnapshotInum         uint32     `struc:"uint32,little"`
	SnapshotID           uint32     `struc:"uint32,little"`
	SnapshotRBlockCount  uint64     `struc:"uint64,little"`
	SnapshotList         uint32     `struc:"uint32,little"`
	ErrorCount           uint32     `struc:"uint32,little"`
	FirstErrorTime       uint32     `struc:"uint32,little"`
	FirstErrorIno        uint32     `struc:"uint32,little"`
	FirstErrorBlock      uint64     `struc:"uint64,little"`
	FirstErrorFunc       [32]byte   `struc:"[32]pad"`
	FirstErrorLine       uint32     `struc:"uint32,little"`
	LastErrorTime        uint32     `struc:"uint32,little"`
	LastErrorIno         uint32     `struc:"uint32,little"`
	LastErrorLine        uint32     `struc:"uint32,little"`
	LastErrorBlock       uint64     `struc:"uint64,little"`
	LastErrorFunc        [32]byte   `struc:"[32]pad"`
	MountOpts            [64]byte   `struc:"[64]pad"`
	UsrQuotaInum         uint32     `struc:"uint32,little"`
	GrpQuotaInum         uint32     `struc:"uint32,little"`
	OverheadClusters     uint32     `struc:"uint32,little"`
	BackupBgs            [2]uint32  `struc:"[2]uint32,little"`
	EncryptAlgos         [4]byte    `struc:"[4]pad"`
	EncryptPwSalt        [16]byte   `struc:"[16]pad"`
	LpfIno               uint32     `struc:"uint32,little"`
	PrjQuotaInum         uint32     `struc:"uint32,little"`
	ChecksumSeed         uint32     `struc:"uint32,little"`
	Reserved             [98]uint32 `struc:"[98]uint32,little"`
	Checksum             uint32     `struc:"uint32,little"`
}

func (sb *Superblock) FeatureCompatDirPrealloc() bool {
	return (sb.FeatureCompat&FEATURE_COMPAT_DIR_PREALLOC != 0)
}
func (sb *Superblock) FeatureCompatImagicInodes() bool {
	return (sb.FeatureCompat&FEATURE_COMPAT_IMAGIC_INODES != 0)
}
func (sb *Superblock) FeatureCompatHas_journal() bool {
	return (sb.FeatureCompat&FEATURE_COMPAT_HAS_JOURNAL != 0)
}
func (sb *Superblock) FeatureCompatExtAttr() bool {
	return (sb.FeatureCompat&FEATURE_COMPAT_EXT_ATTR != 0)
}
func (sb *Superblock) FeatureCompatResizeInode() bool {
	return (sb.FeatureCompat&FEATURE_COMPAT_RESIZE_INODE != 0)
}
func (sb *Superblock) FeatureCompatDirIndex() bool {
	return (sb.FeatureCompat&FEATURE_COMPAT_DIR_INDEX != 0)
}
func (sb *Superblock) FeatureCompatSparseSuper2() bool {
	return (sb.FeatureCompat&FEATURE_COMPAT_SPARSE_SUPER2 != 0)
}
func (sb *Superblock) FeatureRoCompatSparseSuper() bool {
	return (sb.FeatureRoCompat&FEATURE_RO_COMPAT_SPARSE_SUPER != 0)
}
func (sb *Superblock) FeatureRoCompatLargeFile() bool {
	return (sb.FeatureRoCompat&FEATURE_RO_COMPAT_LARGE_FILE != 0)
}
func (sb *Superblock) FeatureRoCompatBtreeDir() bool {
	return (sb.FeatureRoCompat&FEATURE_RO_COMPAT_BTREE_DIR != 0)
}
func (sb *Superblock) FeatureRoCompatHugeFile() bool {
	return (sb.FeatureRoCompat&FEATURE_RO_COMPAT_HUGE_FILE != 0)
}
func (sb *Superblock) FeatureRoCompatGdtCsum() bool {
	return (sb.FeatureRoCompat&FEATURE_RO_COMPAT_GDT_CSUM != 0)
}
func (sb *Superblock) FeatureRoCompatDirNlink() bool {
	return (sb.FeatureRoCompat&FEATURE_RO_COMPAT_DIR_NLINK != 0)
}
func (sb *Superblock) FeatureRoCompatExtraIsize() bool {
	return (sb.FeatureRoCompat&FEATURE_RO_COMPAT_EXTRA_ISIZE != 0)
}
func (sb *Superblock) FeatureRoCompatQuota() bool {
	return (sb.FeatureRoCompat&FEATURE_RO_COMPAT_QUOTA != 0)
}
func (sb *Superblock) FeatureRoCompatBigalloc() bool {
	return (sb.FeatureRoCompat&FEATURE_RO_COMPAT_BIGALLOC != 0)
}
func (sb *Superblock) FeatureRoCompatMetadataCsum() bool {
	return (sb.FeatureRoCompat&FEATURE_RO_COMPAT_METADATA_CSUM != 0)
}
func (sb *Superblock) FeatureRoCompatReadonly() bool {
	return (sb.FeatureRoCompat&FEATURE_RO_COMPAT_READONLY != 0)
}
func (sb *Superblock) FeatureRoCompatProject() bool {
	return (sb.FeatureRoCompat&FEATURE_RO_COMPAT_PROJECT != 0)
}

func (sb *Superblock) FeatureIncompatCompression() bool {
	return (sb.FeatureIncompat&FEATURE_INCOMPAT_COMPRESSION != 0)
}
func (sb *Superblock) FeatureIncompatFiletype() bool {
	return (sb.FeatureIncompat&FEATURE_INCOMPAT_FILETYPE != 0)
}
func (sb *Superblock) FeatureIncompatRecover() bool {
	return (sb.FeatureIncompat&FEATURE_INCOMPAT_RECOVER != 0)
}
func (sb *Superblock) FeatureIncompatJournalDev() bool {
	return (sb.FeatureIncompat&FEATURE_INCOMPAT_JOURNAL_DEV != 0)
}
func (sb *Superblock) FeatureIncompatMetaBg() bool {
	return (sb.FeatureIncompat&FEATURE_INCOMPAT_META_BG != 0)
}
func (sb *Superblock) FeatureIncompatExtents() bool {
	return (sb.FeatureIncompat&FEATURE_INCOMPAT_EXTENTS != 0)
}
func (sb *Superblock) FeatureIncompatMmp() bool {
	return (sb.FeatureIncompat&FEATURE_INCOMPAT_MMP != 0)
}
func (sb *Superblock) FeatureIncompatFlexBg() bool {
	return (sb.FeatureIncompat&FEATURE_INCOMPAT_FLEX_BG != 0)
}
func (sb *Superblock) FeatureIncompatEaInode() bool {
	return (sb.FeatureIncompat&FEATURE_INCOMPAT_EA_INODE != 0)
}
func (sb *Superblock) FeatureIncompatDirdata() bool {
	return (sb.FeatureIncompat&FEATURE_INCOMPAT_DIRDATA != 0)
}
func (sb *Superblock) FeatureIncompatCsumSeed() bool {
	return (sb.FeatureIncompat&FEATURE_INCOMPAT_CSUM_SEED != 0)
}
func (sb *Superblock) FeatureIncompatLargedir() bool {
	return (sb.FeatureIncompat&FEATURE_INCOMPAT_LARGEDIR != 0)
}
func (sb *Superblock) FeatureIncompatInlineData() bool {
	return (sb.FeatureIncompat&FEATURE_INCOMPAT_INLINE_DATA != 0)
}
func (sb *Superblock) FeatureIncompatEncrypt() bool {
	return (sb.FeatureIncompat&FEATURE_INCOMPAT_ENCRYPT != 0)
}

func (sb *Superblock) FeatureInCompat64bit() bool {
	return (sb.FeatureIncompat&FEATURE_INCOMPAT_64BIT != 0)
}

func (sb *Superblock) GetBlockCount() int64 {
	if sb.FeatureInCompat64bit() {
		return (int64(sb.BlockCountHi) << 32) | int64(sb.BlockCountLo)
	}
	return int64(sb.BlockCountLo)
}

func (sb *Superblock) GetGroupDescriptorTableCount() uint32 {
	return (sb.BlockCountHi<<32|sb.BlockCountLo)/sb.BlockPerGroup + 1
}

func (sb *Superblock) GetGroupDescriptorCount() uint32 {
	if sb.FeatureInCompat64bit() {
		return (sb.GetGroupDescriptorTableCount() * 64 / 1024) + 1
	}
	return (sb.GetGroupDescriptorTableCount() * 32 / 1024) + 1
}

func (sb *Superblock) GetBlockSize() int64 {
	return int64(1024 << uint(sb.LogBlockSize))
}

func (sb *Superblock) GetGroupsPerFlex() int64 {
	return 1 << sb.LogGroupPerFlex
}
