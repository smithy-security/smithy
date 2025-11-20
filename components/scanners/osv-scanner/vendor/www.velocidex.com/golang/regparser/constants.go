package regparser

const (
	REG_NONE                       = 0x00000000
	REG_SZ                         = 0x00000001
	REG_EXPAND_SZ                  = 0x00000002
	REG_BINARY                     = 0x00000003
	REG_DWORD                      = 0x00000004
	REG_DWORD_LITTLE_ENDIAN        = 0x00000004
	REG_DWORD_BIG_ENDIAN           = 0x00000005
	REG_LINK                       = 0x00000006
	REG_MULTI_SZ                   = 0x00000007
	REG_RESOURCE_LIST              = 0x00000008
	REG_FULL_RESOURCE_DESCRIPTOR   = 0x00000009
	REG_RESOURCE_REQUIREMENTS_LIST = 0x0000000a
	REG_QWORD                      = 0x0000000b

	REG_UNKNOWN = 0xffffffff
)

func RegTypeToString(reg_type uint32) string {
	switch reg_type {
	case 0x00000000:
		return "REG_NONE"
	case 0x00000001:
		return "REG_SZ"
	case 0x00000002:
		return "REG_EXPAND_SZ"
	case 0x00000003:
		return "REG_BINARY"
	case 0x00000004:
		return "REG_DWORD"
	case 0x00000005:
		return "REG_DWORD_BIG_ENDIAN"
	case 0x00000006:
		return "REG_LINK"
	case 0x00000007:
		return "REG_MULTI_SZ"
	case 0x00000008:
		return "REG_RESOURCE_LIST"
	case 0x00000009:
		return "REG_FULL_RESOURCE_DESCRIPTOR"
	case 0x0000000a:
		return "REG_RESOURCE_REQUIREMENTS_LIST"
	case 0x0000000b:
		return "REG_QWORD"
	}

	return "REG_UNKNOWN"
}
