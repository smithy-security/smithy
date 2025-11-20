package parser

import "fmt"

type InodeFormatter struct {
	attr_ids []uint32
}

// Format an inode unambigously
func (self *InodeFormatter) Inode(mft_id uint32,
	attr_type_id uint64, attr_id uint16, name string) string {
	inode := fmt.Sprintf("%d-%d-%d", mft_id, attr_type_id, attr_id)
	needle := uint32(attr_id)<<16 + uint32(attr_type_id)

	if inSliceUint32(needle, self.attr_ids) {
		// Only include the name if it is necessary (i.e. there is
		// another stream of the same type-id).
		if name != "" {
			inode += ":" + name
		}
	} else {
		// This is O(n) but there should not be too many items.
		self.attr_ids = append(self.attr_ids, needle)
	}

	return inode
}

func inSliceUint32(needle uint32, haystack []uint32) bool {
	for _, i := range haystack {
		if i == needle {
			return true
		}
	}
	return false
}
