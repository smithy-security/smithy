package parser

import (
	"path"
)

func get_display_name(file_names []*FILE_NAME) string {
	short_name := ""
	for _, fn := range file_names {
		name := fn.Name()
		name_type := fn.NameType().Name
		switch name_type {
		case "Win32", "DOS+Win32", "POSIX":
			return name
		default:
			short_name = name
		}
	}

	return short_name
}

// Traverse the mft entry and attempt to find its owner until the
// root. We return the full path of the MFT entry.
func GetFullPath(ntfs *NTFSContext, mft_entry *MFT_ENTRY) string {
	links := GetHardLinks(ntfs, uint64(mft_entry.Record_number()), 1)
	if len(links) == 0 {
		return "/"
	}
	return "/" + path.Join(links[0]...)
}

func CapUint64(v uint64, max uint64) uint64 {
	if v > max {
		return max
	}
	return v
}

func CapUint32(v uint32, max uint32) uint32 {
	if v > max {
		return max
	}
	return v
}

func CapUint16(v uint16, max uint16) uint16 {
	if v > max {
		return max
	}
	return v
}

func CapInt64(v int64, max int64) int64 {
	if v > max {
		return max
	}
	return v
}

func CapInt32(v int32, max int32) int32 {
	if v > max {
		return max
	}
	return v
}

func setADS(components []string, name string) []string {
	result := make([]string, 0, len(components))
	for i, c := range components {
		if i < len(components)-1 {
			result = append(result, c)
		} else {
			result = append(result, c+":"+name)
		}
	}
	return result
}

func CopySlice(in []string) []string {
	result := make([]string, len(in))
	copy(result, in)
	return result
}

// In place reserving of the slice
func ReverseStringSlice(s []string) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}
