package regparser

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

// Model a registry hive with this object.
type Registry struct {
	Reader io.ReaderAt

	Profile   *RegistryProfile
	BaseBlock *HBASE_BLOCK
}

func NewRegistry(reader io.ReaderAt) (*Registry, error) {
	self := &Registry{
		Reader:  reader,
		Profile: NewRegistryProfile(),
	}
	self.BaseBlock = self.Profile.HBASE_BLOCK(reader, 0)
	if self.BaseBlock.Signature() != 0x66676572 {
		return nil, errors.New("File does not have registry magic.")
	}

	return self, nil
}

// A helper method to open a key by path.
func (self *Registry) OpenKey(key_path string) *CM_KEY_NODE {
	root_cell := self.Profile.HCELL(self.Reader,
		0x1000+int64(self.BaseBlock.RootCell()))

	nk := root_cell.KeyNode()
	if nk == nil {
		return nil
	}

subkey_match:
	for _, component := range SplitComponents(key_path) {
		if component == "" {
			continue
		}

		component = strings.ToLower(component)

		for _, subkey := range nk.Subkeys() {
			if strings.ToLower(subkey.Name()) == component {
				nk = subkey
				continue subkey_match
			}
		}

		// If we get here we could not find the key:
		return nil
	}

	return nk
}

// RecoverHive copies the hive to another file and applies the dirty pages
// from the log files.
//
// Returns a File object pointing to the recovered Hive. The caller is
// responsible for deleting the recovered hive file.
func RecoverHive(hive *os.File, logFiles ...*os.File) (*os.File, error) {
	var (
		exitErr            error
		baseRegistry       *Registry
		logRegistries      []*Registry
		headerUpdateNeeded bool
	)

	newHiveFile, err := os.CreateTemp(os.TempDir(), "")
	if err != nil {
		return nil, fmt.Errorf("cannot create new hive file (%v)", err)
	}

	_, err = io.Copy(newHiveFile, hive)
	if err != nil {
		exitErr = fmt.Errorf("cannot copy hive (%v)", err)
		goto fail
	}

	baseRegistry, err = NewRegistry(newHiveFile)
	if err != nil {
		exitErr = fmt.Errorf("cannot parse base hive (%v)", err)
		goto fail
	}

	if calculateChecksum(newHiveFile) != baseRegistry.BaseBlock.CheckSum() {
		headerUpdateNeeded = true
	}

	for _, l := range logFiles {
		if s, err := l.Stat(); err != nil {
			exitErr = fmt.Errorf("stat syscall on file %s failed (%v)",
				l.Name(), err)
			goto fail
		} else if s.Size() == 0 {
			fmt.Printf("[info] Registry Hive %s empty: skipping\n", l.Name())
			continue
		}
		logReg, err := NewRegistry(l)
		if err != nil {
			exitErr = fmt.Errorf("invalid Registry Hive in log file %s (%v)",
				l.Name(), err)
			goto fail
		}

		if logReg.BaseBlock.Type() == 1 || logReg.BaseBlock.Type() == 2 {
			fmt.Printf("[warn] version %d of log file '%s' not supported. skipping\n",
				logReg.BaseBlock.Type(), l.Name())
			continue
		}

		if logReg.BaseBlock.Sequence1() < baseRegistry.BaseBlock.Sequence2() {
			log.Printf("[info] skipping log file %s, sequence number mismatch (log starts at sequence number %d, base is already at %d)\n",
				l.Name(), logReg.BaseBlock.Sequence1(),
				baseRegistry.BaseBlock.Sequence2())
			continue
		}

		logRegistries = append(logRegistries, logReg)
	}

	if len(logRegistries) == 2 {
		// find the one to apply first
		one := logRegistries[0]
		two := logRegistries[1]

		if one.BaseBlock.Sequence1() > two.BaseBlock.Sequence1() {
			logRegistries[0], logRegistries[1] = logRegistries[1], logRegistries[0]
		}
	} else if len(logRegistries) > 2 {
		exitErr = fmt.Errorf("got more than two log files, unsupported")
		goto fail
	}

	// iterate log entries and write dirty pages to base Hive
	for _, logRegistry := range logRegistries {
		logEntryOffset := int64(0x200) // hard-coded offset, always 0x200

		var hbinsSize, sequenceNumber, hiveFlags uint32

		for hasBytesLeft(logRegistry.Reader, logEntryOffset) {
			logEntry := &HIVE_LOG_ENTRY{
				Reader:  logRegistry.Reader,
				Offset:  logEntryOffset,
				Profile: NewRegistryProfile()}

			if logEntry.Signature() != 0x454C7648 { // HvLE magic bytes
				exitErr = fmt.Errorf("HvLE block at %#x has an invalid signature", logEntryOffset)
				goto fail
			}

			if logEntry.SequenceNumber() == logRegistry.BaseBlock.Sequence2() {
				// we reached the last valid log entry of the file
				break
			}

			for _, page := range logEntry.GetDirtyPages() {
				data, err := page.Data()
				if err != nil {
					exitErr = fmt.Errorf("cannot read dirty page data (%v)", err)
					goto fail
				}

				// offset to first hbin is always 0x1000, page offset is relative to that
				n, err := newHiveFile.WriteAt(data, int64(page.PageOffset)+0x1000)
				if n != int(page.PageSize) || err != nil {
					exitErr = fmt.Errorf("cannot write page of size %#x at offset %#x (%v)",
						page.PageSize, page.PageOffset, err)
					goto fail
				}
			}

			hbinsSize = logEntry.HiveBinsDataSize()
			sequenceNumber = logEntry.SequenceNumber()
			hiveFlags = logEntry.Flags()

			logEntryOffset += int64(logEntry.LogEntrySize())
		}

		if headerUpdateNeeded {
			buf := make([]byte, 4)

			binary.LittleEndian.PutUint32(buf, sequenceNumber)
			newHiveFile.WriteAt(buf, 4)
			newHiveFile.WriteAt(buf, 8)

			binary.LittleEndian.PutUint32(buf, hbinsSize)
			newHiveFile.WriteAt(buf, 0x28)

			binary.LittleEndian.PutUint32(buf, hiveFlags)
			newHiveFile.WriteAt(buf, 0x90)

			binary.LittleEndian.PutUint32(buf, calculateChecksum(newHiveFile))
			newHiveFile.WriteAt(buf, 0x1fC)
		}
	}

	return newHiveFile, nil

fail:
	newHiveFile.Close()
	os.Remove(newHiveFile.Name())
	return nil, exitErr
}

func hasBytesLeft(reader io.ReaderAt, offset int64) bool {
	buf := make([]byte, 1)
	if n, err := reader.ReadAt(buf, offset); n != 1 || err != nil {
		return false
	}
	return true
}

func calculateChecksum(reader io.ReaderAt) uint32 {
	buf := make([]byte, 0x1fc)
	_, err := reader.ReadAt(buf, 0)
	if err != nil {
		return 0
	}

	checksum := uint32(0)

	for i := 0; i < 0x1fc; i += 4 {
		checksum ^= binary.LittleEndian.Uint32(buf[i : i+4])
	}

	if checksum == 0 {
		return 1
	} else if checksum == 0xFFFFFFFF {
		return 0xFFFFFFFE
	} else {
		return checksum
	}
}
