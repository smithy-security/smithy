package exfat

import (
	"unicode/utf16"
)

// UnicodeFromAscii returns Unicode from raw utf16 data.
func UnicodeFromAscii(raw []byte, unicodeCharCount int) string {
	// `VolumeLabel` is a Unicode-encoded string and the character-count
	// corresponds to the number of Unicode characters. The character-count may
	// still include trailing NULs, sowe intentional skip over those.

	decodedString := make([]rune, 0)
	for i := 0; i < unicodeCharCount; i++ {
		wchar1 := uint16(raw[i*2+1])
		wchar2 := uint16(raw[i*2])

		bytes := []uint16{wchar1<<8 | wchar2}
		runes := utf16.Decode(bytes)

		if runes[0] == 0 {
			continue
		}

		decodedString = append(decodedString, runes...)
	}

	return string(decodedString)
}
