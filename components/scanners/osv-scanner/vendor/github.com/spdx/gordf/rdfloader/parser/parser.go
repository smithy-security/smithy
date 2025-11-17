package parser

import (
	"fmt"
	xmlreader "github.com/spdx/gordf/rdfloader/xmlreader"
	"github.com/spdx/gordf/uri"
	"strings"
	"sync"
)

const RDFNS = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"

type Parser struct {
	setTriples       map[string]*Triple
	setNodes         map[string]*Node
	Triples          []*Triple
	writeLock        sync.RWMutex
	nodesWriteLock   sync.RWMutex
	SchemaDefinition map[string]uri.URIRef
	blankNodeGetter  BlankNodeGetter
	rdfNS            uri.URIRef
	wg               sync.WaitGroup
}

func parseHeaderBlock(rootBlock xmlreader.Block) (map[string]uri.URIRef, error) {
	// returns all the schema definitions in the root block.
	// a schema definition is of the form xmlns:SchemaName="URI",

	namespaceURI := map[string]uri.URIRef{}

	// boolean to indicate if we got any uri same as parser.RDFNS
	anyRDFURI := false

	for _, attr := range rootBlock.OpeningTag.Attrs {
		if attr.SchemaName == "xmlns" {
			uriref, err := uri.NewURIRef(attr.Value)
			if err != nil {
				return namespaceURI, fmt.Errorf("schema URI %v doesn't confirm to URL rules", attr.Value)
			}
			if strings.TrimSuffix(uriref.String(), "#") == strings.TrimSuffix(RDFNS, "#") {
				anyRDFURI = true
			}
			namespaceURI[attr.Name] = uriref
		} else if attr.SchemaName == "" && attr.Name == "xmlns" {
			uriref, err := uri.NewURIRef(attr.Value)
			if err != nil {
				return namespaceURI, err
			}
			namespaceURI[attr.SchemaName] = uriref
		}
	}

	// rdfAbbrevPresent: true if user has mapped "rdf" to another uri
	_, rdfAbbrevPresent := namespaceURI["rdf"]
	if !anyRDFURI && !rdfAbbrevPresent {
		rdfURI, _ := uri.NewURIRef(RDFNS)
		namespaceURI["rdf"] = rdfURI
	}
	return namespaceURI, nil
}

func (parser *Parser) getRDFAttributeIndex(tag xmlreader.Tag, attrName string) (index int, err error) {
	/*
		From all the attribute of the given tag, return the index of the attribute rdf:attrName
	*/
	index = -1
	for i, attr := range tag.Attrs {
		attrUri, err := parser.uriFromPair(attr.SchemaName, attr.Name)
		if err != nil {
			break
		}
		if attrUri == parser.rdfNS.AddFragment(attrName) {
			// current attribute is a rdf:attrName tag,
			index = i
			break
		}
	}
	return
}

func getLastURI(tag xmlreader.Tag, lastURI string) string {
	for _, attr := range tag.Attrs {
		if attr.SchemaName == "" && attr.Name == "xmlns" {
			return attr.Value
		}
	}
	return lastURI
}

func New() (parser *Parser) {
	// creates a new parser object
	rdfNS, _ := uri.NewURIRef(RDFNS)
	return &Parser{
		setTriples:       map[string]*Triple{},
		setNodes:         map[string]*Node{},
		Triples:          []*Triple{},
		writeLock:        sync.RWMutex{},
		nodesWriteLock:   sync.RWMutex{},
		SchemaDefinition: map[string]uri.URIRef{"": uri.URIRef{}},
		blankNodeGetter:  BlankNodeGetter{-1},
		wg:               sync.WaitGroup{},
		rdfNS:            rdfNS,
	}
}

func (parser *Parser) parseBlock(currBlock *xmlreader.Block, node *Node, lastURI string, errp *error) {
	/*
		1. What is a block?
		Ans: A rdf block is made up of
				1. Root Node (IRI Ref or BlankNode) :: Subject
				2. Link (IRI Ref)                   :: Object
				3. anotherBlock (Literal or IRI Ref or Blank Node) :: Predicate

		2. Example of a Block.
			Sample RDF/XML input with non-blank subject and literal predicate.
				<spdx:License rdf:about="http://spdx.org/licenses/Apache-2.0">
					<spdx:licenseId>Apache-2.0</spdx:licenseId>
				</spdx:License>
			Output Components:
				Subject:   http://spdx.org/licenses/Apache-2.0  (IRI Ref)
				Object:    spdx:licenseId						(IRI Ref)
				Predicate: Apacha-2.0							(Literal)
			If the rdf:about attribute of the subject is removed, it will become a blank node.

		3. What is a node *Node?
		Ans: effectively, node representation of the block parameter.
			 node := parser.nodeFromTag(block)

		4. Parameter errp.
			Pointer to an error variable.
			used to report errors in a concurrent environment.
			why pointer? Because go func() cannot return anything.
	*/
	node = parser.resolveNode(node)
	defer parser.wg.Done()
	lastURI = getLastURI(currBlock.OpeningTag, lastURI)
	if len(currBlock.Children) == 0 {
		// adding only one triple which identifies the type of the current block.
		predicateURI := parser.rdfNS.AddFragment("type")
		openingTagUri, newErr := parser.uriFromPair(currBlock.OpeningTag.SchemaName, currBlock.OpeningTag.Name)
		if newErr != nil {
			*errp = newErr
			return
		}
		parser.appendTriple(&Triple{
			Subject:   node,
			Predicate: &Node{IRI, predicateURI.String()},
			Object:    &Node{IRI, openingTagUri.String()},
		})
		return
	}
	for _, predicateBlock := range currBlock.Children {
		// predicateURI can't be a blank node. It has to be a URI Reference
		//     according to https://www.w3.org/TR/rdf-concepts/#dfn-predicate
		predicateURI, newErr := parser.uriFromPair(predicateBlock.OpeningTag.SchemaName, predicateBlock.OpeningTag.Name)
		if newErr != nil {
			*errp = fmt.Errorf("error creating a reference URI link for the predicate block. %v", newErr)
			return
		}
		predicateNode := &Node{NodeType: IRI, ID: predicateURI.String()}

		openingTagUri, newErr := parser.uriFromPair(currBlock.OpeningTag.SchemaName, currBlock.OpeningTag.Name)
		if newErr != nil {
			*errp = newErr
			return
		}

		// (node) -> rdf:type -> (openingTagURI)
		predicateURI = parser.rdfNS.AddFragment("type")
		parser.appendTriple(&Triple{
			Subject:   node,
			Predicate: &Node{IRI, predicateURI.String()},
			Object:    &Node{IRI, openingTagUri.String()},
		})
		if len(predicateBlock.Children) == 0 {
			// no children.
			currentTriple := &Triple{
				Subject:   node,
				Predicate: predicateNode,
				Object:    nil,
			}
			resIdx, newErr := parser.getRDFAttributeIndex(predicateBlock.OpeningTag, "resource")
			*errp = newErr
			if *errp != nil {
				return
			}
			nodeidIdx, newErr := parser.getRDFAttributeIndex(predicateBlock.OpeningTag, "nodeID")
			*errp = newErr
			if *errp != nil {
				return
			}

			switch {
			case resIdx != -1:
				// rdf:resource attribute is present
				currentTriple.Object = &Node{
					NodeType: RESOURCELITERAL,
					ID:       predicateBlock.OpeningTag.Attrs[resIdx].Value,
				}
			case nodeidIdx != -1:
				// we have a reference to another block via rdf:nodeID
				currentTriple.Object = &Node{
					NodeType: NODEIDLITERAL,
					ID:       parser.blankNodeGetter.GetFromId(predicateBlock.OpeningTag.Attrs[nodeidIdx].Value).ID,
				}
			default:
				// it is a literal node without any special attributes
				resIdx, newErr = parser.getRDFAttributeIndex(predicateBlock.OpeningTag, "nodeID")
				currentTriple.Object = &Node{
					NodeType: LITERAL,
					ID:       predicateBlock.Value,
				}
			}

			// registering a new Triple:
			parser.appendTriple(currentTriple)
		}

		// the predicate block has children
		for _, objectBlock := range predicateBlock.Children {
			objectNode, newErr := parser.nodeFromTag(objectBlock.OpeningTag, lastURI)
			if newErr != nil {
				*errp = newErr
				return
			}

			parser.appendTriple(&Triple{
				Subject:   node,
				Predicate: predicateNode,
				Object:    objectNode,
			})
			parser.wg.Add(1)
			go parser.parseBlock(objectBlock, objectNode, lastURI, errp)
			if *errp != nil {
				return
			}
		}
	}
}

func (parser *Parser) Parse(rootBlock xmlreader.Block) (err error) {
	// set all the schema definitions in the root block.
	schemaDefinition, err := parseHeaderBlock(rootBlock)
	if err != nil {
		return err
	}
	parser.SchemaDefinition = schemaDefinition

	// root tag is set now.
	var childNode *Node
	xmlns := schemaDefinition[""]
	xmlnsString := xmlns.String()
	for _, child := range rootBlock.Children {
		childNode, err = parser.nodeFromTag(child.OpeningTag, xmlnsString)
		if err != nil {
			return err
		}
		parser.wg.Add(1)
		go parser.parseBlock(child, childNode, xmlnsString, &err)
		if err != nil {
			return err
		}
	}
	parser.wg.Wait() // wait for all the go routines to finish executing.
	return err
}
