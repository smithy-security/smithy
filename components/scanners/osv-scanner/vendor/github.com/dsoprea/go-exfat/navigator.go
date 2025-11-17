// This package supports enumerating/indexing the entries for a single
// directory.

package exfat

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/dsoprea/go-logging"
)

const (
	// This field is mandatory and Section 6.1 defines its contents.
	directoryEntryBytesCount = 32
)

// ExfatNavigator knows how to get and manipulate the entries of a single
// directory.
type ExfatNavigator struct {
	er                 *ExfatReader
	firstClusterNumber uint32
}

// NewExfatNavigator returns a new ExfatNavigator instance.
func NewExfatNavigator(er *ExfatReader, firstClusterNumber uint32) (en *ExfatNavigator) {
	return &ExfatNavigator{
		er:                 er,
		firstClusterNumber: firstClusterNumber,
	}
}

// DirectoryEntryVisitorFunc is a function type used as a callback over each
// file directory entry.
type DirectoryEntryVisitorFunc func(primaryEntry DirectoryEntry, secondaryEntries []DirectoryEntry) (err error)

// EnumerateDirectoryEntries will enumerate each primary directory entry
// associated with the given file along with an secondary entries that they're
// associated with.
func (en *ExfatNavigator) EnumerateDirectoryEntries(cb DirectoryEntryVisitorFunc) (visitedClusters, visitedSectors []uint32, err error) {
	defer func() {
		if errRaw := recover(); errRaw != nil {
			err = log.Wrap(errRaw.(error))
		}
	}()

	// TODO(dustin): Add test.

	// Enumerate clusters.

	entryNumber := 0
	isDone := false

	var primaryEntry DirectoryEntry
	var secondaryEntries []DirectoryEntry

	visitedClusters = make([]uint32, 0)
	visitedSectors = make([]uint32, 0)

	cvf := func(ec *ExfatCluster) (doContinue bool, err error) {
		defer func() {
			if errRaw := recover(); errRaw != nil {
				var ok bool
				if err, ok = errRaw.(error); ok == true {
					err = log.Wrap(err)
				} else {
					err = log.Errorf("Error not an error: [%s] [%v]", reflect.TypeOf(err).Name(), err)
				}
			}
		}()

		visitedClusters = append(visitedClusters, ec.ClusterNumber())

		// Enumerate sectors.

		svf := func(sectorNumber uint32, data []byte) (doContinue bool, err error) {
			defer func() {
				if errRaw := recover(); errRaw != nil {
					var ok bool
					if err, ok = errRaw.(error); ok == true {
						err = log.Wrap(err)
					} else {
						err = log.Errorf("Error not an error: [%s] [%v]", reflect.TypeOf(err).Name(), err)
					}
				}
			}()

			visitedSectors = append(visitedSectors, sectorNumber)
			sectorSize := en.er.SectorSize()

			i := 0
			for {
				directoryEntryData := data[i*directoryEntryBytesCount : (i+1)*directoryEntryBytesCount]

				entryType := EntryType(directoryEntryData[0])

				// We've hit the terminal record.
				if entryType.IsEndOfDirectory() == true {
					isDone = true
					return false, nil
				}

				de, err := parseDirectoryEntry(entryType, directoryEntryData)
				log.PanicIf(err)

				if entryType.IsPrimary() == true {
					primaryEntry = de

					// We'll always overwrite the primary as part of our
					// process. Note that any secordary entries that we
					// encounter will be appended to `secondaryEntries` but
					// unless the last primary entry indicate that it wanted any
					// of those secondary entries, they'll be forgotten.
					secondaryEntries = make([]DirectoryEntry, 0)
				} else {
					secondaryEntries = append(secondaryEntries, de)
				}

				// If the primary entry did not have a secondary entry
				// requirement, or it did and we've met it, call the callback.
				if pde, ok := primaryEntry.(PrimaryDirectoryEntry); ok == true {
					if len(secondaryEntries) == int(pde.SecondaryCount()) {
						err := cb(primaryEntry, secondaryEntries)
						log.PanicIf(err)
					}
				} else if entryType.IsPrimary() == true {
					// We're conceding the presence of primary entry-types that
					// don't necessarily have a SecondaryCount field (which is
					// the qualification to be considered a
					// `PrimaryDirectoryEntry`). Therefore, if our primary was
					// not a `PrimaryDirectoryEntry` *but* it's still
					// purportedly a primary entry, call the callback with an
					// empty list for the secondary entries (the
					// `secondaryEntries` entry list will always be empty here
					// due to above).

					err := cb(primaryEntry, secondaryEntries)
					log.PanicIf(err)
				}

				entryNumber++

				i++

				if uint32(i*directoryEntryBytesCount) >= sectorSize {
					break
				}
			}

			return true, nil
		}

		err = ec.EnumerateSectors(svf)
		log.PanicIf(err)

		if isDone == true {
			return false, nil
		}

		return true, nil
	}

	// The specification is unclear whether the directory-entry clusters are
	// inline (useFat == false) or use the FAT. However, this seems to imply
	// that it's one long chain:
	//
	// (from the 6.13 "Directory Structure" table):
	//
	// 	"N, the number of DirectoryEntry fields, is the size, in bytes, of the
	// 	cluster chain which contains the given directory, divided by the size of
	// 	a DirectoryEntry field, 32 bytes."
	//
	// So, we'll instruct the enumerator to visit adjacent cluster chains.
	useFat := false

	err = en.er.EnumerateClusters(en.firstClusterNumber, cvf, useFat)
	log.PanicIf(err)

	return visitedClusters, visitedSectors, nil
}

// IndexedDirectoryEntry is an organization type that the raw directory entries
// associated with a primary directory entry are assigned into.
type IndexedDirectoryEntry struct {
	PrimaryEntry     DirectoryEntry
	SecondaryEntries []DirectoryEntry
	Extra            map[string]interface{}
}

// DirectoryEntryIndex is a collection of all indexed-directory-entries in a
// specific directory. This is colloquially referred to simply as an "index".
type DirectoryEntryIndex map[string][]IndexedDirectoryEntry

// Dump prints a bunch of information about an index.
func (dei DirectoryEntryIndex) Dump() {
	fmt.Printf("Directory Entry Index\n")
	fmt.Printf("=====================\n")
	fmt.Printf("\n")

	for typeName, ideList := range dei {
		fmt.Printf("%s\n", typeName)
		fmt.Println(strings.Repeat("-", len(typeName)))
		fmt.Printf("\n")

		for i, ide := range ideList {
			fmt.Printf("# %d\n", i)
			fmt.Printf("\n")

			fmt.Printf("  Primary: %s\n", ide.PrimaryEntry)

			for j, secondaryEntry := range ide.SecondaryEntries {
				fmt.Printf("  Secondary (%d): %s\n", j, secondaryEntry)
			}

			fmt.Printf("\n")

			if len(ide.Extra) > 0 {
				fmt.Printf("  Extra:\n")

				for k, v := range ide.Extra {
					fmt.Printf("    %s: %s\n", k, v)
				}

				fmt.Printf("\n")
			}

			if fdf, ok := ide.PrimaryEntry.(*ExfatFileDirectoryEntry); ok == true {
				fmt.Printf("  Attributes:\n")

				fdf.FileAttributes.DumpBareIndented("    ")

				fmt.Printf("\n")
			}
		}
	}
}

// Filenames returns a map of all filenames in the directory and whether they
// are directories or just files.
func (dei DirectoryEntryIndex) Filenames() (filenames map[string]bool) {
	fileIdeList, found := dei["File"]
	if found == true {
		filenames = make(map[string]bool, len(fileIdeList))
		for _, ide := range fileIdeList {
			filename := ide.Extra["complete_filename"].(string)
			filenames[filename] = ide.PrimaryEntry.(*ExfatFileDirectoryEntry).FileAttributes.IsDirectory()
		}
	} else {
		filenames = make(map[string]bool, 0)
	}

	return filenames
}

// FileCount returns the number of files in the directory.
func (dei DirectoryEntryIndex) FileCount() (count int) {
	if fileIdeList, found := dei["File"]; found == true {
		count = len(fileIdeList)
	}

	return count
}

// GetFile returns the file directory-entry with index `i`.
func (dei DirectoryEntryIndex) GetFile(i int) (filename string, fdf *ExfatFileDirectoryEntry) {
	ide := dei["File"][i]
	return ide.Extra["complete_filename"].(string), ide.PrimaryEntry.(*ExfatFileDirectoryEntry)
}

// FindIndexedFile returns an IDE for a given file.
func (dei DirectoryEntryIndex) FindIndexedFile(filename string) (ide IndexedDirectoryEntry, found bool) {
	for i := 0; i < dei.FileCount(); i++ {
		ide := dei["File"][i]
		if ide.Extra["complete_filename"].(string) == filename {
			return ide, true
		}
	}

	return ide, false
}

// FindIndexedFileDirectoryEntry returns the i'th occurrence of the given entry-
// type under the given file.
func (dei DirectoryEntryIndex) FindIndexedFileDirectoryEntry(filename, entryTypeName string, i int) (de DirectoryEntry) {
	ide, found := dei.FindIndexedFile(filename)
	if found == false {
		return nil
	}

	if ide.PrimaryEntry.TypeName() == entryTypeName {
		// Since there are no collisions between primary and secondary entry-
		// type names, if they entered a primary entry-type name and a non-zero
		// index, this must've been intentional but a mistake.
		if i != 0 {
			log.Panicf("index must be zero when searching for a primary directory-entry type: [%s] (%d)", entryTypeName, i)
		}

		return ide.PrimaryEntry
	}

	hits := 0
	for _, currentDe := range ide.SecondaryEntries {
		if currentDe.TypeName() == entryTypeName {
			if hits == i {
				return currentDe
			}

			hits++
		}
	}

	return nil
}

// FindIndexedFileFileDirectoryEntry is a convenience function to get the FDE
// for the given file.
func (dei DirectoryEntryIndex) FindIndexedFileFileDirectoryEntry(filename string) (fdf *ExfatFileDirectoryEntry) {
	de := dei.FindIndexedFileDirectoryEntry(filename, "File", 0)
	if de == nil {
		return nil
	}

	return de.(*ExfatFileDirectoryEntry)
}

// FindIndexedFileStreamExtensionDirectoryEntry is a convenience function to get
// the SEDE for the given file.
func (dei DirectoryEntryIndex) FindIndexedFileStreamExtensionDirectoryEntry(filename string) (sede *ExfatStreamExtensionDirectoryEntry) {
	de := dei.FindIndexedFileDirectoryEntry(filename, "StreamExtension", 0)
	if de == nil {
		return nil
	}

	return de.(*ExfatStreamExtensionDirectoryEntry)
}

// IndexDirectoryEntries builds an index for the current directory.
func (en *ExfatNavigator) IndexDirectoryEntries() (index DirectoryEntryIndex, visitedClusters, visitedSectors []uint32, err error) {
	defer func() {
		if errRaw := recover(); errRaw != nil {
			err = log.Wrap(errRaw.(error))
		}
	}()

	index = make(DirectoryEntryIndex)

	cb := func(primaryEntry DirectoryEntry, secondaryEntries []DirectoryEntry) (err error) {
		extra := make(map[string]interface{})

		ide := IndexedDirectoryEntry{
			PrimaryEntry:     primaryEntry,
			SecondaryEntries: secondaryEntries,
			Extra:            extra,
		}

		if _, ok := primaryEntry.(*ExfatFileDirectoryEntry); ok == true {
			mf := MultipartFilename(secondaryEntries)
			completeFilename := mf.Filename()

			extra["complete_filename"] = completeFilename
		}

		typeName := primaryEntry.TypeName()
		if ideList, found := index[typeName]; found == true {
			index[typeName] = append(ideList, ide)
		} else {
			index[typeName] = []IndexedDirectoryEntry{ide}
		}

		return nil
	}

	visitedClusters, visitedSectors, err = en.EnumerateDirectoryEntries(cb)
	log.PanicIf(err)

	return index, visitedClusters, visitedSectors, nil
}
