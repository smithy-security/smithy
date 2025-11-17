package rdfloader

import (
	"bufio"
	"os"
	"unicode"
)

const WHITESPACE uint64 = 1<<'\t' | 1<<'\n' | 1<<'\r' | 1<<' '

type XMLReader struct {
	fileReader *bufio.Reader
	fileObj    *os.File
}

/*
An attribute is of the form schemaName:tagName="value" which exists inside an opening tag.
For example:-
If the opening tag is:
	<rdf:RDF
		xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
    	xmlns:doap="http://usefulinc.com/ns/doap#">
Attributes are given by :-
	1. SchemaName=xmlns, Name=rdf, Value=http://www.w3.org/1999/02/22-rdf-syntax-ns#
	2. SchemaName=xmlns, Name=doap, Value=http://usefulinc.com/ns/doap#
*/
type Attribute struct {
	Name       string
	SchemaName string
	Value      string
}

type Pair struct {
	First  interface{}
	Second interface{}
}

type Tag struct {
	SchemaName string
	Name       string
	Attrs      []Attribute
}

type Block struct {
	// A block is a valid sub-xml.
	// for example:
	// 		1. <tag />
	// 		2. <tag attr="attr" />
	//      3. <tag> value </tag>
	//      4. <parent> <child> value </child> </parent>
	OpeningTag Tag
	Value      string
	Children   []*Block
}

// returns next character in the file without affecting the file pointer
func (xmlReader *XMLReader) peekARune() (r rune, err error) {
	singleByte, err := xmlReader.fileReader.Peek(1)
	if err != nil {
		return r, err
	} else {
		return rune(singleByte[0]), nil
	}
}

// returns next character in the file which advances the file pointer.
func (xmlReader *XMLReader) readARune() (rune, error) {
	singleByteArray := make([]byte, 1)
	_, err := xmlReader.fileReader.Read(singleByteArray)
	return rune(singleByteArray[0]), err
}

func (xmlReader *XMLReader) readTill(delim uint64) ([]rune, error) {
	// reads the input file rune by rune till the target rune is found
	//		or eof is reached.
	// Note: it doesn't include the target rune in the read word.
	var buffer []rune
	for {
		r, err := xmlReader.fileReader.Peek(1)
		if err == nil {
			// checking if the read rune is same as any of the delimiters' mask
			if (delim & (1 << r[0])) != 0 {
				// current char is same as one of the delimiters.
				return buffer, nil
			}

			// moving file pointer one character ahead.
			xmlReader.readARune()

			// current character is not one of the delimiters.
			buffer = append(buffer, rune(r[0]))
		} else {
			return buffer, err
		}
	}
}

func (xmlReader *XMLReader) readTillString(delimiter string) ([]byte, error) {
	// reads the input file rune by rune till the target rune is found
	//		or eof is reached.
	// Note: it doesn't include the target rune in the read word.
	var buffer []byte
	for {
		b, err := xmlReader.peekNBytes(len(delimiter))
		if err != nil {
			// flush the output when any error occurs
			return []byte{}, err
		}
		// checking if the read rune is same as any of the delimiters' mask
		if string(b) == delimiter {
			return buffer, nil
		}

		// moving file pointer n characters ahead.
		xmlReader.readARune()

		// current string doesn't match the given delimiter.
		buffer = append(buffer, b[0])
	}
}

// read N bytes from the file without affecting the file pointer.
func (xmlReader *XMLReader) peekNBytes(n int) ([]byte, error) {
	return xmlReader.fileReader.Peek(n)
}

// read N bytes from the file advancing the file pointer by N.
func (xmlReader *XMLReader) readNBytes(n int) ([]byte, error) {
	var output []byte
	for n > 0 {
		buffer := make([]byte, n)
		nBytesRead, err := xmlReader.fileReader.Read(buffer)
		if err != nil {
			return output, err
		}
		n -= nBytesRead
		output = append(output, buffer[:nBytesRead]...)
	}
	return output, nil
}

// advance the file pointer until a non-blank character is found.
func (xmlReader *XMLReader) ignoreWhiteSpace() (nWS int, err error) {
	// nWS: number of whitespaces which were stripped.
	for {
		char, err := xmlReader.peekARune()
		if err != nil || !unicode.IsSpace(char) {
			return nWS, err
		}
		nWS++
		xmlReader.readARune()
	}
}
