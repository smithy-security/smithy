/*
Decompression support for the LZNT1 compression algorithm.

Reference:
http://msdn.microsoft.com/en-us/library/jj665697.aspx
(2.5 LZNT1 Algorithm Details)

https://github.com/libyal/reviveit/
https://github.com/sleuthkit/sleuthkit/blob/develop/tsk/fs/ntfs.c
*/

package parser

import (
	"encoding/binary"
	"errors"
)

var (
	COMPRESSED_MASK = uint16(1 << 15)
	SIGNATURE_MASK  = uint16(3 << 12)
	SIZE_MASK       = uint16(1<<12) - 1

	shiftTooLargeError = errors.New(
		"Decompression error - shift is too large")
	blockTooSmallError = errors.New("Block too small!")
)

func get_displacement(offset uint16) byte {
	result := byte(0)
	for {
		if offset < 0x10 {
			return result
		}

		offset >>= 1
		result += 1
	}
}

func LZNT1Decompress(in []byte) ([]byte, error) {
	debugLZNT1Decompress("LZNT1Decompress in:\n%s\n", debugHexDump(in))

	// Index into the in buffer
	i := 0
	out := []byte{}

	for {
		if len(in) < i+2 {
			break
		}
		uncompressed_chunk_offset := len(out)
		block_offset := i

		block_header := binary.LittleEndian.Uint16(in[i:])
		debugLZNT1Decompress("Header %#x @ %#x %d\n", block_header, i, i)
		i += 2

		size := int(block_header & SIZE_MASK)
		block_end := block_offset + size + 3
		debugLZNT1Decompress("%d Block Size: %x ends at %x\n", len(out), size+3, block_end)
		if size == 0 {
			break
		}

		if len(in) < i+size {
			return nil, blockTooSmallError
		}

		if block_header&COMPRESSED_MASK != 0 {
			for i < block_end {
				header := uint8(in[i])
				debugLZNT1Decompress("%d Header Tag %02x\n", len(out), header)
				i++

				for mask_idx := uint8(0); mask_idx < 8 && i < block_end; mask_idx++ {
					if (header & 1) == 0 {
						debugLZNT1Decompress("  %d: Symbol %02x (%d)\n", i, in[i], len(out))
						out = append(out, in[i])
						i++

					} else {
						pointer := binary.LittleEndian.Uint16(in[i:])
						i += 2

						displacement := get_displacement(
							uint16(len(out) - uncompressed_chunk_offset - 1))
						symbol_offset := int(pointer>>(12-displacement)) + 1
						symbol_length := int(pointer&(0xFFF>>displacement)) + 2
						start_offset := len(out) - symbol_offset
						for j := 0; j < symbol_length+1; j++ {
							idx := start_offset + j
							if idx < 0 || idx >= len(out) {
								debugLZNT1Decompress(
									"idx %v, pointer %v, displacement %v out\n %v\n",
									idx, pointer, displacement,
									debugHexDump(out))
								return out, shiftTooLargeError
							}
							out = append(out, out[idx])
						}
					}
					header >>= 1
				}
			}

			// Block is not compressed.
		} else {
			out = append(out, in[i:i+size+1]...)
			i += size + 1
		}

	}

	debugLZNT1Decompress("decompression out %v\n", len(out))
	return out, nil
}
