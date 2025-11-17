package parser

import (
	"fmt"
	xmlreader "github.com/spdx/gordf/rdfloader/xmlreader"
	"github.com/spdx/gordf/uri"
	"strings"
)

type Triple struct {
	Subject, Predicate, Object *Node
}

func (parser *Parser) appendTriple(triple *Triple) {
	// does what it say.
	// appends the triples to the parser.
	// uses a lock for mutex to prevent race condition.

	// writelock is a type of RWMutex.
	// RW is Readers-Writer Lock. That is, at a time, more than on e readers
	//		can read from the data structure but at a time only one writer can
	//		access the data structure.
	parser.writeLock.Lock()
	if _, exists := parser.setTriples[triple.Hash()]; !exists {
		// append to the map and triples' set if it doesn't already exist in the map.
		parser.setTriples[triple.Hash()] = triple
		parser.Triples = append(parser.Triples, triple)
	}
	parser.writeLock.Unlock()
}

func (parser *Parser) resolveNode(node *Node) *Node {
	parser.nodesWriteLock.Lock()
	defer parser.nodesWriteLock.Unlock()
	existingNode := parser.setNodes[node.String()]
	if existingNode != nil {
		return existingNode
	} else {
		parser.setNodes[node.String()] = node
	}
	return node
}

func (parser *Parser) uriFromPair(schemaName, name string) (mergedUri uri.URIRef, err error) {
	// returns the uri representation of a pair of strings.
	// name:schemaName is an example of pair.
	// pairs such as rdf:RDF, where, rdf must be a valid xmlns schema name.

	// base must be a valid schema name defined in the root tag.
	baseURI, ok := parser.SchemaDefinition[schemaName]
	if !ok {
		return uri.URIRef{}, fmt.Errorf("undefined schema name: %v", schemaName)
	}

	// adding the relative fragment to the base uri.
	return baseURI.AddFragment(name), nil
}

func (parser *Parser) convertRdfIdToRdfAbout(tag xmlreader.Tag) (error) {
	idx, err := parser.getRDFAttributeIndex(tag, "ID")
	if err != nil {
		return err
	}
	if idx == -1 {
		return nil
	}
	// we've found a rdf:ID attribute. converting it into rdf:about attribute.
	// converting rdf:ID="val" to rdf:about="#val"
	tag.Attrs[idx].Name = "about"
	tag.Attrs[idx].Value = "#" + tag.Attrs[idx].Value
	return nil
}

func (parser *Parser) nodeFromTag(openingTag xmlreader.Tag, lastURI string) (node *Node, err error) {
	// returns the node object from the opening tag of any block.
	// https://www.w3.org/TR/rdf-syntax-grammar/figure1.png has sample image having 5 nodes.
	// 		one of them is a blank node.

	// description of the entire function:
	// if the opening tag has an attribute of rdf:about,
	//		the node will represented by the value of rdf:about attribute
	// else, it is a blank node.

	err = parser.convertRdfIdToRdfAbout(openingTag)
	if err != nil {
		return nil, err
	}

	// checking if any of the attributes is a rdf:about attribute
	index, err := parser.getRDFAttributeIndex(openingTag, "about")
	if err != nil {
		return
	}

	var currentNode Node
	if index != -1 {
		// we found a rdf:about tag.
		currentNode.NodeType = IRI
		currentNode.ID = openingTag.Attrs[index].Value
		if strings.HasPrefix(currentNode.ID, "#") {
			// the predicate uri is a relative uri. it must be resolve using the base lastURI
			baseURI, err := uri.NewURIRef(lastURI)
			if err != nil {
				return nil, err
			}
			resolvedURI := baseURI.AddFragment(currentNode.ID)
			currentNode.ID = resolvedURI.String()
		}
		return &currentNode, nil
	}

	// we don't have rdf:about attribute, returning a new blank node.
	rdfNodeIDIndex, err := parser.getRDFAttributeIndex(openingTag, "nodeID")
	if err != nil {
		return nil, err
	}
	if rdfNodeIDIndex == -1 {
		currentNode = parser.blankNodeGetter.Get()
	} else {
		currentNode = parser.blankNodeGetter.GetFromId(openingTag.Attrs[rdfNodeIDIndex].Value)
	}
	return &currentNode, nil
}

func (triple *Triple) Hash() string {
	return fmt.Sprintf("{%v; %v; %v}", triple.Subject, triple.Predicate, triple.Object)
}
