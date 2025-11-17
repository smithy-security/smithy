package plist

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"reflect"
	"time"
)

const xmlDOCTYPE = `<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">`
const plistStart = `<plist version="1.0">`
const plistEnd = `</plist>`

type xmlEncoder struct {
	indent      string
	indentCount int
	err         error
	writer      io.Writer
	*xml.Encoder
}

func (e *xmlEncoder) write(buf []byte) {
	if e.err != nil {
		return
	}
	_, e.err = e.writer.Write(buf)
}

func newXMLEncoder(w io.Writer) *xmlEncoder {
	return &xmlEncoder{writer: w, Encoder: xml.NewEncoder(w)}
}

func (e *xmlEncoder) generateDocument(pval *plistValue) error {
	e.write([]byte(xml.Header))
	e.write([]byte(xmlDOCTYPE))
	e.write([]byte("\n"))
	e.write([]byte(plistStart))
	if e.indent != "" {
		e.write([]byte("\n"))
	}

	if err := e.writePlistValue(pval); err != nil {
		return err
	}

	if e.indent != "" {
		e.write([]byte("\n"))
	}
	e.write([]byte(plistEnd))
	e.write([]byte("\n"))
	return e.err
}

func (e *xmlEncoder) writePlistValue(pval *plistValue) error {
	switch pval.kind {
	case String:
		return e.writeStringValue(pval)
	case Boolean:
		return e.writeBoolValue(pval)
	case Integer:
		return e.writeIntegerValue(pval)
	case Dictionary:
		return e.writeDictionaryValue(pval)
	case Date:
		return e.writeDateValue(pval)
	case Array:
		return e.writeArrayValue(pval)
	case Real:
		return e.writeRealValue(pval)
	case Data:
		return e.writeDataValue(pval)
	default:
		return &UnsupportedTypeError{reflect.ValueOf(pval.value).Type()}
	}
}

func (e *xmlEncoder) writeDataValue(pval *plistValue) error {
	encodedValue := base64.StdEncoding.EncodeToString(pval.value.([]byte))
	return e.EncodeElement(encodedValue, xml.StartElement{Name: xml.Name{Local: "data"}})
}

func (e *xmlEncoder) writeRealValue(pval *plistValue) error {
	encodedValue := pval.value
	switch {
	case math.IsInf(pval.value.(sizedFloat).value, 1):
		encodedValue = "inf"
	case math.IsInf(pval.value.(sizedFloat).value, -1):
		encodedValue = "-inf"
	case math.IsNaN(pval.value.(sizedFloat).value):
		encodedValue = "nan"
	default:
		encodedValue = pval.value.(sizedFloat).value
	}
	return e.EncodeElement(encodedValue, xml.StartElement{Name: xml.Name{Local: "real"}})
}

// writeElement writes an xml element like <plist>, <array> or <dict>
func (e *xmlEncoder) writeElement(name string, pval *plistValue, valFunc func(*plistValue) error) error {
	startElement := xml.StartElement{
		Name: xml.Name{
			Space: "",
			Local: name,
		},
	}

	if name == "dict" || name == "array" {
		e.indentCount++
	}

	// Encode xml.StartElement token
	if err := e.EncodeToken(startElement); err != nil {
		return err
	}

	// flush
	if err := e.Flush(); err != nil {
		return err
	}

	// execute valFunc()
	if err := valFunc(pval); err != nil {
		return err
	}

	// Encode xml.EndElement token
	if err := e.EncodeToken(startElement.End()); err != nil {
		return err
	}

	if name == "dict" || name == "array" {
		e.indentCount--
	}

	// flush
	return e.Flush()
}

func (e *xmlEncoder) writeArrayValue(pval *plistValue) error {
	tokenFunc := func(pval *plistValue) error {
		encodedValue := pval.value
		values := encodedValue.([]*plistValue)
		wroteBool := false
		for _, v := range values {
			if !wroteBool {
				wroteBool = v.kind == Boolean
			}
			if err := e.writePlistValue(v); err != nil {
				return err
			}
		}

		if e.indent != "" && wroteBool {
			e.writer.Write([]byte("\n"))
			e.writer.Write([]byte(e.indent))
		}
		return nil
	}
	return e.writeElement("array", pval, tokenFunc)

}

func (e *xmlEncoder) writeDictionaryValue(pval *plistValue) error {
	tokenFunc := func(pval *plistValue) error {
		encodedValue := pval.value
		dict := encodedValue.(*dictionary)
		dict.populateArrays()
		for i, k := range dict.keys {
			if err := e.EncodeElement(k, xml.StartElement{Name: xml.Name{Local: "key"}}); err != nil {
				return err
			}
			if err := e.writePlistValue(dict.values[i]); err != nil {
				return err
			}
		}
		return nil
	}
	return e.writeElement("dict", pval, tokenFunc)
}

// encode strings as CharData, which doesn't escape newline
// see https://github.com/golang/go/issues/9204
func (e *xmlEncoder) writeStringValue(pval *plistValue) error {
	startElement := xml.StartElement{Name: xml.Name{Local: "string"}}
	// Encode xml.StartElement token
	if err := e.EncodeToken(startElement); err != nil {
		return err
	}

	// flush
	if err := e.Flush(); err != nil {
		return err
	}

	stringValue := pval.value.(string)
	if err := e.EncodeToken(xml.CharData(stringValue)); err != nil {
		return err
	}

	// flush
	if err := e.Flush(); err != nil {
		return err
	}

	// Encode xml.EndElement token
	if err := e.EncodeToken(startElement.End()); err != nil {
		return err
	}

	// flush
	return e.Flush()

}

func (e *xmlEncoder) writeBoolValue(pval *plistValue) error {
	// EncodeElement results in <true></true> instead of <true/>
	// use writer to write self closing tags
	b := pval.value.(bool)
	if e.indent != "" {
		e.write([]byte("\n"))
		for i := 0; i < e.indentCount; i++ {
			e.write([]byte(e.indent))
		}
	}
	e.write([]byte(fmt.Sprintf("<%t/>", b)))
	return e.err
}

func (e *xmlEncoder) writeIntegerValue(pval *plistValue) error {
	encodedValue := pval.value
	if pval.value.(signedInt).signed {
		encodedValue = int64(pval.value.(signedInt).value)
	} else {
		encodedValue = pval.value.(signedInt).value
	}
	return e.EncodeElement(encodedValue, xml.StartElement{Name: xml.Name{Local: "integer"}})
}

func (e *xmlEncoder) writeDateValue(pval *plistValue) error {
	encodedValue := pval.value.(time.Time).In(time.UTC).Format(time.RFC3339)
	return e.EncodeElement(encodedValue, xml.StartElement{Name: xml.Name{Local: "date"}})
}
