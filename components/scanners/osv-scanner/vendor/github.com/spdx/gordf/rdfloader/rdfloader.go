package rdfloader

import (
	"bufio"
	"github.com/spdx/gordf/rdfloader/parser"
	xmlreader "github.com/spdx/gordf/rdfloader/xmlreader"
	"io"
	"os"
)

// given a file path, parse it and return the Parser object
func LoadFromFilePath(filePath string) (parserObj *parser.Parser, err error) {
	file, err := os.Open(filePath)
	if err != nil {
		return
	}
	return LoadFromReaderObject(file)
}

// LoadFromReaderObj take an io.Reader object and returns a list of triples.
//     if there is no error parsing the document.
func LoadFromReaderObject(fileObj io.Reader) (parserObj *parser.Parser, err error) {
	// reader for xml file
	reader := xmlreader.XMLReaderFromFileObject(bufio.NewReader(fileObj))

	// parsing the xml content of the file.
	rootBlock, err := reader.Read()
	if err != nil {
		return
	}

	// creating a new Parser
	rdfParser := parser.New()
	err = rdfParser.Parse(rootBlock)
	if err != nil {
		return
	}
	return rdfParser, nil
}
