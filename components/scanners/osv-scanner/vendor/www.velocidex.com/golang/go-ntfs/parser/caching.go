// Manage caching of MFT Entry metadata. This is mainly used for path
// traversal calculation.

package parser

import "sync"

type FNSummary struct {
	Name                 string
	NameType             string
	ParentEntryNumber    uint64
	ParentSequenceNumber uint16
}

type MFTEntrySummary struct {
	Sequence  uint16
	Filenames []FNSummary
}

type MFTEntryCache struct {
	mu sync.Mutex

	ntfs *NTFSContext

	lru *LRU
}

func NewMFTEntryCache(ntfs *NTFSContext) *MFTEntryCache {
	lru, _ := NewLRU(10000, nil, "MFTEntryCache")
	return &MFTEntryCache{
		ntfs: ntfs,
		lru:  lru,
	}
}

func (self *MFTEntryCache) GetSummary(id uint64) (*MFTEntrySummary, error) {
	self.mu.Lock()
	defer self.mu.Unlock()

	res_any, pres := self.lru.Get(int(id))
	if pres {
		res, ok := res_any.(*MFTEntrySummary)
		if ok {
			return res, nil
		}
	}

	mft_entry, err := self.ntfs.GetMFT(int64(id))
	if err != nil {
		return nil, err
	}

	cache_record := &MFTEntrySummary{
		Sequence: mft_entry.Sequence_value(),
	}
	for _, fn := range mft_entry.FileName(self.ntfs) {
		cache_record.Filenames = append(cache_record.Filenames,
			FNSummary{
				Name:                 fn.Name(),
				NameType:             fn.NameType().Name,
				ParentEntryNumber:    fn.MftReference(),
				ParentSequenceNumber: fn.Seq_num(),
			})
	}

	self.lru.Add(int(id), cache_record)
	return cache_record, nil
}
