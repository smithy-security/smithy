package rdfwriter

import (
	"fmt"
	"github.com/spdx/gordf/rdfloader/parser"
	"github.com/spdx/gordf/uri"
	"io"
	"strings"
)

//  returns the triples that matches the input subject, object and the predicate.
// reason behind using string pointers is that it allows the user to pass a nil
// if the user is unsure about the other types.
// For example, if the user wants all the triples with subject rdf:about, the
// user can call FilterTriples(triples, &rdfAboutString, nil, nil)
// where, rdfAboutString := "rdf:about"
func FilterTriples(triples []*parser.Triple, subject, predicate, object *string) (result []*parser.Triple) {
	for _, triple := range triples {
		if (subject == nil || *subject == triple.Subject.ID) && (predicate == nil || *predicate == triple.Predicate.ID) && (object == nil || *object == triple.Object.ID) {
			result = append(result, triple)
		}
	}
	return
}

// returns the string form of the root tag with all the uri definitions
func getRootTagFromSchemaDefinition(schemaDefinition map[string]uri.URIRef, tab string) string {
	rootTag := "<rdf:RDF\n"
	for tag := range schemaDefinition {
		tagURI := schemaDefinition[tag]
		if tag == "" {
			rootTag += tab + fmt.Sprintf(`%s="%s"`, "xmlns", tagURI.String()) + "\n"
		} else {
			rootTag += tab + fmt.Sprintf(`%s:%s="%s"`, "xmlns", tag, tagURI.String()) + "\n"
		}
	}
	rootTag = rootTag[:len(rootTag)-1] // removing the last \n char.
	rootTag += ">"
	return rootTag
}

// returns the string form of the opening and closing tag from the given triples.
func getOpeningAndClosingTags(triples []*parser.Triple, rdfNSAbbrev string, invSchemaDefinition map[string]string, tabs string, node *parser.Node) (openingTag string, closingTag string, err error) {
	rdfTypeURI := parser.RDFNS + "type"
	rdfNodeIDURI := parser.RDFNS + "nodeID"

	openingTagFormat := "<%s%s%s>"
	closingTagFormat := "</%s>"
	// taking example of the following tag:
	//   <spdx:name rdf:nodeID="ID" rdf:about="https://sample.com#name">Apache License 2.0</spdx:name>
	// Description of the %s used in the openingTagFormat
	// 1st %s: node's name and schemaName
	// 		   spdx:name in case of the example
	// 2nd %s: nodeId attribute
	//         rdf:nodeID="ID" for the given example
	// 3rd %s: rdf:about property
	//         rdf:about="https://sample.com#name" for the given example
	// NOTE: 2nd and 3rd %s can be given in any order. won't affect the semantics of the output.
	// Description of the %s used in the closingTagFormat:
	// 1st %s: same as first %s of openingTagFormat

	rdfTypeTriples := FilterTriples(triples, nil, &rdfTypeURI, nil)
	if n := len(rdfTypeTriples); n != 1 {
		return openingTag, closingTag, fmt.Errorf("every subject node must be associated with exactly 1 triple of type rdf:type predicate. Found %v triples", n)
	}
	rdfnodeIDTriples := FilterTriples(triples, nil, &rdfNodeIDURI, nil)
	if n := len(rdfnodeIDTriples); n > 1 {
		return openingTag, closingTag, fmt.Errorf("there must be atmost nodeID attribute. found %v nodeID attributes", n)
	}

	rdfNodeID := ""
	if len(rdfnodeIDTriples) == 1 {
		rdfNodeID = fmt.Sprintf(` %s:nodeID="%s"`, rdfNSAbbrev, rdfnodeIDTriples[0].Object.ID)
	}
	rdfAbout := ""
	if node.NodeType == parser.IRI {
		rdfAbout = fmt.Sprintf(` %s:about="%s"`, rdfNSAbbrev, node.ID)
	}

	tagName, err := shortenURI(rdfTypeTriples[0].Object.ID, invSchemaDefinition)
	if err != nil {
		return openingTag, closingTag, err
	}

	openingTag = tabs + fmt.Sprintf(openingTagFormat, tagName, rdfNodeID, rdfAbout)
	closingTag = tabs + fmt.Sprintf(closingTagFormat, tagName)
	return openingTag, closingTag, nil
}

// returns the string equivalent of the triples associated with the given node in rdf/xml format.
func stringify(node *parser.Node, nodeToTriples map[string][]*parser.Triple, invSchemaDefinition map[string]string, depth int, tab string) (output string, err error) {
	// Any rdf/xml tag is formed of OpeningTag, childrenString, ClosingTag
	var openingTag, childrenString, closingTag string

	tabs := strings.Repeat(tab, depth)

	// getting the abbreviation used for rdf namespace.
	rdfNSAbbrev := getRDFNSAbbreviation(invSchemaDefinition)

	openingTag, closingTag, err = getOpeningAndClosingTags(nodeToTriples[node.String()], rdfNSAbbrev, invSchemaDefinition, tabs, node)
	if err != nil {
		return
	}

	// getting rest of the triples after rdf attributes are parsed
	restTriples := getRestTriples(nodeToTriples[node.String()])

	depth++     // we'll be parsing one level deep now.
	tabs += tab // or strings.Repeat(tab, depth)
	for _, triple := range restTriples {
		predicateURI, err := shortenURI(triple.Predicate.ID, invSchemaDefinition)
		if err != nil {
			return "", err
		}

		if triple.Object.NodeType == parser.RESOURCELITERAL {
			childrenString += tabs + fmt.Sprintf(`<%s %s:resource="%s"/>`, predicateURI, rdfNSAbbrev, triple.Object.ID) + "\n"
			continue
		}

		var childString string
		// adding opening tag to the child tag:
		childString += tabs + fmt.Sprintf("<%s>", predicateURI) + "\n"
		if len(nodeToTriples[triple.Object.String()]) == 0 {
			// the tag ends here and doesn't have any further childs.
			// object is even one level deep
			// number of tabs increases.
			childString += strings.Repeat(tab, depth+1) + triple.Object.ID
		} else {
			// we have a sub-child which is not a literal type. it can be a blank or a IRI node.
			temp, err := stringify(triple.Object, nodeToTriples, invSchemaDefinition, depth+1, tab)
			if err != nil {
				return "", err
			}
			childString += temp
		}
		// adding the closing tag
		childString += "\n" + tabs + fmt.Sprintf("</%s>", predicateURI)
		childrenString += childString + "\n"
	}
	childrenString = strings.TrimSuffix(childrenString, "\n")
	return fmt.Sprintf("%s\n%v\n%s", openingTag, childrenString, closingTag), nil
}

// function provided to the user for converting triples to string.
// Arg Description:
//   triples: list of triples of a rdf graph
//   schemaDefinition: maps the prefix given by xmlns to the URI
//   tab: tab character to be used in the output. It can be four-spaces,
//        two-spaces, single tab character, double tab character, etc
//        depending upon the choice of the user.
func TriplesToString(triples []*parser.Triple, schemaDefinition map[string]uri.URIRef, tab string) (outputString string, err error) {
	// linearly ordering the triples in a non-increasing order of depth.
	sortedTriples, err := TopologicalSortTriples(triples)
	if err != nil {
		return outputString, err
	}

	invSchemaDefinition := invertSchemaDefinition(schemaDefinition)
	nodeToTriples := GetNodeToTriples(sortedTriples)
	rootTags := GetRootNodes(sortedTriples)

	// now, we can iterate over all the root-nodes and generate the string representation of the nodes.
	for _, tag := range rootTags {
		currString, err := stringify(tag, nodeToTriples, invSchemaDefinition, 1, tab)
		if err != nil {
			return outputString, err
		}
		outputString += currString + "\n"
	}
	rootTagString := getRootTagFromSchemaDefinition(schemaDefinition, tab)
	rootEndTag := "</rdf:RDF>"
	return fmt.Sprintf("%s\n%s%s", rootTagString, outputString, rootEndTag), nil
}

// converts the input triples to string and writes it to the file.
// Args Description:
//   w: writer in which the output data will be written.
//   rest all params are same as that of the TriplesToString function.
func WriteToFile(w io.Writer, triples []*parser.Triple, schemaDefinition map[string]uri.URIRef, tab string) error {
	opString, err := TriplesToString(triples, schemaDefinition, tab)
	if err != nil {
		return err
	}
	_, err = fmt.Fprint(w, opString)
	return err
}
