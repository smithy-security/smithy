// This package supports browsing the filesystem at the tree level.

package exfat

import (
	"sort"
	"strings"

	"github.com/dsoprea/go-logging"
)

// TreeNode represents a single file or directory.
type TreeNode struct {
	name string

	isDirectory bool

	ide  IndexedDirectoryEntry
	sede *ExfatStreamExtensionDirectoryEntry
	fde  *ExfatFileDirectoryEntry

	loaded bool

	childrenFolders sort.StringSlice
	childrenFiles   sort.StringSlice

	childrenMap map[string]*TreeNode
}

// NewTreeNode returns a new instance of TreeNode.
func NewTreeNode(name string, isDirectory bool, ide IndexedDirectoryEntry, fde *ExfatFileDirectoryEntry, sede *ExfatStreamExtensionDirectoryEntry) (tn *TreeNode) {
	childrenList := make(sort.StringSlice, 0)
	childrenMap := make(map[string]*TreeNode)

	tn = &TreeNode{
		name:        name,
		isDirectory: isDirectory,

		ide:  ide,
		sede: sede,
		fde:  fde,

		childrenFolders: childrenList,
		childrenFiles:   childrenList,

		childrenMap: childrenMap,
	}

	return tn
}

// Name returns the name of the current file or directory (without any of its
// parents' path information).
func (tn *TreeNode) Name() string {
	return tn.name
}

// IndexedDirectoryEntry returns the underlying, low-level directory-entry
// information that were retrieved for this directory.
func (tn *TreeNode) IndexedDirectoryEntry() IndexedDirectoryEntry {
	return tn.ide
}

// FileDirectoryEntry returns the FDE for the current directory (it's actually a
// part of the IDE but this is important and is nicer to have directly
// available).
func (tn *TreeNode) FileDirectoryEntry() *ExfatFileDirectoryEntry {
	return tn.fde
}

// StreamDirectoryEntry returns the SEDE for the current directory (it's
// actually a part of the IDE but this is important and is nicer to have
// directly available).
func (tn *TreeNode) StreamDirectoryEntry() *ExfatStreamExtensionDirectoryEntry {
	return tn.sede
}

// IsDirectory indicates whether the node is a directory or not.
func (tn *TreeNode) IsDirectory() bool {
	return tn.isDirectory
}

// ChildFolders lists any child-folders. Only applies to directory nodes.
func (tn *TreeNode) ChildFolders() []string {
	return tn.childrenFolders
}

// ChildFiles lists any child files. Only applies to directory nodes.
func (tn *TreeNode) ChildFiles() []string {
	return tn.childrenFiles
}

// GetChild a particular child node.
func (tn *TreeNode) GetChild(filename string) *TreeNode {
	return tn.childrenMap[filename]
}

// Lookup finds the given relative path within our children.
func (tn *TreeNode) Lookup(pathParts []string) (lastPathParts []string, lastNode *TreeNode, found *TreeNode) {
	if len(pathParts) == 0 {
		// We've reached and found the last part.
		return nil, nil, tn
	}

	childNode := tn.childrenMap[pathParts[0]]
	if childNode == nil {
		// An intermediate part was not found.
		return pathParts, tn, nil
	}

	lastPathParts, lastNode, found = childNode.Lookup(pathParts[1:])
	return lastPathParts, lastNode, found
}

// AddChild registers a new child to this node. It's stored in sorted order.
func (tn *TreeNode) AddChild(name string, isDirectory bool, fde *ExfatFileDirectoryEntry, sede *ExfatStreamExtensionDirectoryEntry, ide IndexedDirectoryEntry) *TreeNode {
	childNode := NewTreeNode(name, isDirectory, ide, fde, sede)

	// The adds are driven through a process based on a map, so the order will
	// always be random. Use insertion sort to order the children so their order
	// is deterministic.

	var list sort.StringSlice
	if isDirectory == true {
		list = tn.childrenFolders
	} else {
		list = tn.childrenFiles
	}

	insertOrEqualAt := list.Search(name)

	if insertOrEqualAt >= len(list) {
		list = append(list, name)
	} else if list[insertOrEqualAt] != name {
		leftHalf := list[:insertOrEqualAt]
		rightHalf := list[insertOrEqualAt:]
		list = append(leftHalf, append([]string{name}, rightHalf...)...)
	}

	if isDirectory == true {
		tn.childrenFolders = list
	} else {
		tn.childrenFiles = list
	}

	tn.childrenMap[name] = childNode

	return childNode
}

// Tree is a higher-level struct that wraps the root-node.
type Tree struct {
	er       *ExfatReader
	rootNode *TreeNode
}

// NewTree returns a new Tree instance.
func NewTree(er *ExfatReader) *Tree {
	rootNode := NewTreeNode("", true, IndexedDirectoryEntry{}, nil, nil)

	return &Tree{
		er:       er,
		rootNode: rootNode,
	}
}

func (tree *Tree) loadDirectory(clusterNumber uint32, node *TreeNode) (err error) {
	defer func() {
		if errRaw := recover(); errRaw != nil {
			err = log.Wrap(errRaw.(error))
		}
	}()

	en := NewExfatNavigator(tree.er, clusterNumber)

	index, _, _, err := en.IndexDirectoryEntries()
	log.PanicIf(err)

	filenames := index.Filenames()

	for filename, isDirectory := range filenames {
		ide, found := index.FindIndexedFile(filename)
		if found != true {
			log.Panicf("could not find indexed-entry for filename that definitely exists: [%s]", filename)
		}

		fde := index.FindIndexedFileFileDirectoryEntry(filename)
		sede := index.FindIndexedFileStreamExtensionDirectoryEntry(filename)

		// Since we load lazily, we won't immediately load the child.
		node.AddChild(filename, isDirectory, fde, sede, ide)
	}

	node.loaded = true

	return nil
}

// Load loads the whole tree.
func (tree *Tree) Load() (err error) {
	defer func() {
		if errRaw := recover(); errRaw != nil {
			err = log.Wrap(errRaw.(error))
		}
	}()

	clusterNumber := tree.er.FirstClusterOfRootDirectory()

	err = tree.loadDirectory(clusterNumber, tree.rootNode)
	log.PanicIf(err)

	return nil
}

// Lookup finds the node for the given absolute path.
func (tree *Tree) Lookup(pathParts []string) (node *TreeNode, err error) {
	defer func() {
		if errRaw := recover(); errRaw != nil {
			err = log.Wrap(errRaw.(error))
		}
	}()

	startNode := tree.rootNode

	for {
		lastPathParts, lastNode, foundNode := startNode.Lookup(pathParts)
		if foundNode != nil {
			// The node was found. Make sure that it's fully constituted before
			// returning.

			if foundNode.isDirectory == true && foundNode.loaded == false {
				err := tree.loadDirectory(foundNode.sede.FirstCluster, foundNode)
				log.PanicIf(err)
			}

			return foundNode, nil
		}

		// If we've already loaded all children for that node, return nil (find
		// unsuccessful).
		if lastNode.loaded == true {
			return nil, nil
		}

		err := tree.loadDirectory(lastNode.sede.FirstCluster, lastNode)
		log.PanicIf(err)

		startNode = lastNode
		pathParts = lastPathParts
	}
}

// TreeVisitorFunc is a visitor function that receives a series of visited
// nodes.
type TreeVisitorFunc func(pathParts []string, node *TreeNode) (err error)

// Visit will pass every node in the tree to the given callback.
func (tree *Tree) Visit(cb TreeVisitorFunc) (err error) {
	defer func() {
		if errRaw := recover(); errRaw != nil {
			err = log.Wrap(errRaw.(error))
		}
	}()

	pathParts := make([]string, 0)

	err = tree.visit(pathParts, tree.rootNode, cb)
	log.PanicIf(err)

	return nil
}

func (tree *Tree) visit(pathParts []string, node *TreeNode, cb TreeVisitorFunc) (err error) {
	defer func() {
		if errRaw := recover(); errRaw != nil {
			err = log.Wrap(errRaw.(error))
		}
	}()

	err = cb(pathParts, node)
	log.PanicIf(err)

	for _, childFolderName := range node.childrenFolders {
		childNode := node.childrenMap[childFolderName]

		childPathParts := make([]string, len(pathParts)+1)
		copy(childPathParts, pathParts)
		childPathParts[len(childPathParts)-1] = childNode.name

		// Finish loading node.
		if childNode.loaded == false {
			err := tree.loadDirectory(childNode.sede.FirstCluster, childNode)
			log.PanicIf(err)
		}

		err := tree.visit(childPathParts, childNode, cb)
		log.PanicIf(err)
	}

	// Do the files all at once, at the bottom.
	for _, childFilename := range node.childrenFiles {
		childNode := node.childrenMap[childFilename]

		childPathParts := make([]string, len(pathParts)+1)
		copy(childPathParts, pathParts)
		childPathParts[len(childPathParts)-1] = childFilename

		err := cb(childPathParts, childNode)
		log.PanicIf(err)
	}

	return nil
}

// List returns a complete list of all paths and a map of each of those paths to
// their node instances.
func (tree *Tree) List() (files []string, nodes map[string]*TreeNode, err error) {
	defer func() {
		if errRaw := recover(); errRaw != nil {
			err = log.Wrap(errRaw.(error))
		}
	}()

	files = make([]string, 0)
	nodes = make(map[string]*TreeNode)

	cb := func(pathParts []string, node *TreeNode) (err error) {
		if len(pathParts) == 0 {
			return nil
		}

		nodePath := strings.Join(pathParts, `\`)

		files = append(files, nodePath)
		nodes[nodePath] = node

		return nil
	}

	err = tree.Visit(cb)
	log.PanicIf(err)

	return files, nodes, nil
}
