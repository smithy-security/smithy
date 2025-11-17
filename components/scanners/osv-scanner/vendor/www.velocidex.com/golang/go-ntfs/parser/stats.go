package parser

import (
	"encoding/json"
	"sync"
)

var (
	STATS = Stats{}
)

type Stats struct {
	mu sync.Mutex

	MFT_ENTRY            int
	NTFS_ATTRIBUTE       int
	ATTRIBUTE_LIST_ENTRY int
	STANDARD_INFORMATION int
	FILE_NAME            int
	FixUpDiskMFTEntry    int
	NTFSContext          int
	MFT_ENTRY_attributes int
	MFT_ENTRY_filenames  int
}

func (self *Stats) DebugString() string {
	self.mu.Lock()
	defer self.mu.Unlock()

	serialized, _ := json.MarshalIndent(self, " ", " ")
	return string(serialized)
}

func (self *Stats) Inc_MFT_ENTRY() {
	self.mu.Lock()
	defer self.mu.Unlock()

	self.MFT_ENTRY++
}

func (self *Stats) Inc_NTFSContext() {
	self.mu.Lock()
	defer self.mu.Unlock()

	self.NTFSContext++
}

func (self *Stats) Inc_FixUpDiskMFTEntry() {
	self.mu.Lock()
	defer self.mu.Unlock()

	self.FixUpDiskMFTEntry++
}

func (self *Stats) Inc_NTFS_ATTRIBUTE() {
	self.mu.Lock()
	defer self.mu.Unlock()

	self.NTFS_ATTRIBUTE++
}

func (self *Stats) Inc_ATTRIBUTE_LIST_ENTRY() {
	self.mu.Lock()
	defer self.mu.Unlock()

	self.ATTRIBUTE_LIST_ENTRY++
}

func (self *Stats) Inc_STANDARD_INFORMATION() {
	self.mu.Lock()
	defer self.mu.Unlock()

	self.STANDARD_INFORMATION++
}

func (self *Stats) Inc_FILE_NAME() {
	self.mu.Lock()
	defer self.mu.Unlock()

	self.FILE_NAME++
}

func (self *Stats) Inc_MFT_ENTRY_attributes() {
	self.mu.Lock()
	defer self.mu.Unlock()

	self.MFT_ENTRY_attributes++
}

func (self *Stats) Inc_MFT_ENTRY_filenames() {
	self.mu.Lock()
	defer self.mu.Unlock()

	self.MFT_ENTRY_filenames++
}
