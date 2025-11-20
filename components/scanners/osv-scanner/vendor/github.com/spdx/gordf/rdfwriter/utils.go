package rdfwriter

import (
	"fmt"
	"github.com/spdx/gordf/rdfloader/parser"
	"github.com/spdx/gordf/uri"
	"strings"
)

// returns an adjacency list from a list of triples
// Params:
//   triples: might be unordered
// Output:
//    adjList: adjacency list which maps subject to object for each triple
func GetAdjacencyList(triples []*parser.Triple) (adjList map[*parser.Node][]*parser.Node) {
	// triples are analogous to the edges of a graph.
	// For a (Subject, Predicate, Object) triple,
	// it forms a directed edge from Subject to Object
	// Graphically,
	//                          predicate
	//             (Subject) ---------------> (Object)

	// initialising the adjacency list:
	adjList = make(map[*parser.Node][]*parser.Node)
	for _, triple := range triples {
		// create a new entry in the adjList if the key is not already seen.
		if adjList[triple.Subject] == nil {
			adjList[triple.Subject] = []*parser.Node{}
		}

		// the key is already seen and we can directly append the child
		adjList[triple.Subject] = append(adjList[triple.Subject], triple.Object)

		// ensure that there is a key entry for all the children.
		if adjList[triple.Object] == nil {
			adjList[triple.Object] = []*parser.Node{}
		}
	}
	return adjList
}

// Params:
//   triples: might be unordered
// Output:
//    recoveryDS: subject to triple mapping that will help retrieve the
//                triples after sorting the Subject: Object pairs.
func GetNodeToTriples(triples []*parser.Triple) (recoveryDS map[string][]*parser.Triple) {
	// triples are analogous to the edges of a graph.
	// For a (Subject, Predicate, Object) triple,
	// it forms a directed edge from Subject to Object
	// Graphically,
	//                          predicate
	//             (Subject) ---------------> (Object)

	// initialising the recoveryDS:
	recoveryDS = make(map[string][]*parser.Triple)
	for _, triple := range triples {
		// create a new entry in the recoverDS if the key is not already seen.
		if recoveryDS[triple.Subject.String()] == nil {
			recoveryDS[triple.Subject.String()] = []*parser.Triple{}
		}

		// the key is already seen and we can directly append the child
		recoveryDS[triple.Subject.String()] = append(recoveryDS[triple.Subject.String()], triple)

		// ensure that there is a key entry for all the children.
		if recoveryDS[triple.Object.String()] == nil {
			recoveryDS[triple.Object.String()] = []*parser.Triple{}
		}
	}
	return removeDuplicateTriples(recoveryDS)
}

func getUniqueTriples(triples []*parser.Triple) []*parser.Triple {
	set := map[string]*parser.Triple{}
	for _, triple := range triples {
		set[triple.Hash()] = triple
	}
	var retList []*parser.Triple
	for key := range set {
		retList = append(retList, set[key])
	}
	return retList
}

func removeDuplicateTriples(nodeToTriples map[string][]*parser.Triple) map[string][]*parser.Triple {
	retMap := map[string][]*parser.Triple{}
	for key := range nodeToTriples {
		retMap[key] = getUniqueTriples(nodeToTriples[key])
	}
	return retMap
}

// same as dfs function. Just that after each every neighbor of the node is visited, it is appended in a queue.
// Params:
//     node: Current node to perform dfs on.
//     lastIdx: index where a new node should be added in the resultList
//     visited: if visited[node] is true, we've already serviced the node before.
//     resultList: list of all the nodes after topological sorting.
func topologicalSortHelper(node *parser.Node, lastIndex *int, adjList map[*parser.Node][]*parser.Node, visited *map[*parser.Node]bool, resultList *[]*parser.Node) (err error) {
	if node == nil {
		return
	}

	// checking if the node exist in the graph
	_, exists := adjList[node]
	if !exists {
		return fmt.Errorf("node%v doesn't exist in the graph", *node)
	}
	if (*visited)[node] {
		// this node is already visited.
		// the program enters here when the graph has at least one cycle..
		return
	}

	// marking current node as visited
	(*visited)[node] = true

	// visiting all the neighbors of the node and it's children recursively
	for _, neighbor := range adjList[node] {
		// recurse neighbor only if and only if it is not visited yet.
		if !(*visited)[neighbor] {
			err = topologicalSortHelper(neighbor, lastIndex, adjList, visited, resultList)
			if err != nil {
				return err
			}
		}
	}

	if *lastIndex >= len(adjList) {
		// there is at least one node which is a neighbor of some node
		// whose entry doesn't exist in the adjList
		return fmt.Errorf("found more nodes than the number of keys in the adjacency list")
	}

	// appending from left to right to get a reverse sorted output
	(*resultList)[*lastIndex] = node
	*lastIndex++
	return nil
}

// A wrapper function to initialize the data structures required by the
// topological sort algorithm. It provides an interface to directly get the
// sorted triples without knowing the internal variables required for sorting.
// Note: it sorts in reverse order.
// Params:
//   adjList   : adjacency list: a map with key as the node and value as a
//  			 list of it's neighbor nodes.
// Assumes: all the nodes in the graph are present in the adjList keys.
func topologicalSort(adjList map[*parser.Node][]*parser.Node) ([]*parser.Node, error) {
	// variable declaration
	numberNodes := len(adjList)
	resultList := make([]*parser.Node, numberNodes) //  this will be returned
	visited := make(map[*parser.Node]bool, numberNodes)
	lastIndex := 0

	// iterate through nodes and perform a dfs starting from that node.
	for node := range adjList {
		if !visited[node] {
			err := topologicalSortHelper(node, &lastIndex, adjList, &visited, &resultList)
			if err != nil {
				return resultList, err
			}
		}
	}
	return resultList, nil
}

// Interface for user to provide a list of triples and get the
// sorted one as the output
func TopologicalSortTriples(triples []*parser.Triple) (sortedTriples []*parser.Triple, err error) {
	adjList := GetAdjacencyList(triples)
	recoveryDS := GetNodeToTriples(triples)
	sortedNodes, err := topologicalSort(adjList)
	if err != nil {
		return sortedTriples, fmt.Errorf("error sorting the triples: %v", err)
	}

	// initialized a slice
	sortedTriples = []*parser.Triple{}

	for _, subjectNode := range sortedNodes {
		// append all the triples associated with the subjectNode
		for _, triple := range recoveryDS[subjectNode.String()] {
			sortedTriples = append(sortedTriples, triple)
		}
	}
	return sortedTriples, nil
}

func DisjointSet(triples []*parser.Triple) map[*parser.Node]*parser.Node {
	nodeStringMap := map[string]*parser.Node{}
	parentString := map[string]*parser.Node{}
	for _, triple := range triples {
		parentString[triple.Object.String()] = triple.Subject
		nodeStringMap[triple.Object.String()] = triple.Object
		if _, exists := parentString[triple.Subject.String()]; !exists {
			parentString[triple.Subject.String()] = nil
			nodeStringMap[triple.Subject.String()] = triple.Subject
		}
	}

	parent := make(map[*parser.Node]*parser.Node)
	for keyString := range parentString {
		node := nodeStringMap[keyString]
		parent[node] = parentString[keyString]
	}
	return parent
}

// a schemaDefinition is a dictionary which maps the abbreviation defined in the root tag.
// for example: if the root tag is =>
//      <rdf:RDF
//		    xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"/>
// the schemaDefinition will contain:
//    {"rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#"}
// this function will output a reverse map that is:
//    {"http://www.w3.org/1999/02/22-rdf-syntax-ns#": "rdf"}
func invertSchemaDefinition(schemaDefinition map[string]uri.URIRef) map[string]string {
	invertedMap := make(map[string]string)
	for abbreviation := range schemaDefinition {
		_uri := schemaDefinition[abbreviation]
		invertedMap[strings.Trim(_uri.String(), "#")] = abbreviation
	}
	return invertedMap
}

// return true if the target is in the given list
func any(target string, list []string) bool {
	for _, s := range list {
		if s == target {
			return true
		}
	}
	return false
}

// from the inverted schema definition, returns the name of the prefix used for
// the rdf name space. Return defaults to "rdf"
func getRDFNSAbbreviation(invSchemaDefinition map[string]string) string {
	rdfNSAbbrev := "rdf"
	if abbrev, exists := invSchemaDefinition[parser.RDFNS]; exists {
		rdfNSAbbrev = abbrev
	}
	return rdfNSAbbrev
}

// given an expanded uri, returns abbreviated form for the same.
// For example:
// http://www.w3.org/1999/02/22-rdf-syntax-ns#Description will be abbreviated to rdf:Description
func shortenURI(uri string, invSchemaDefinition map[string]string) (string, error) {
	// Logic: Every uri with a fragment created by the uri.URIRef has if of
	// type baseURI#fragment. This function splits the uri by # character and
	// replaces the baseURI with the abbreviated form from the inverseSchemaDefinition

	splitIndex := strings.LastIndex(uri, "#")
	if splitIndex == -1 {
		return "", fmt.Errorf("uri doesn't have two parts of type schemaName:tagName. URI: %s", uri)
	}

	baseURI := strings.Trim(uri[:splitIndex], "#")
	fragment := strings.TrimSuffix(uri[splitIndex+1:], "#") // removing the trailing #.
	fragment = strings.TrimSpace(fragment)
	if len(fragment) == 0 {
		return "", fmt.Errorf(`fragment "%v" doesn't exist`, fragment)
	}
	if abbrev, exists := invSchemaDefinition[baseURI]; exists {
		if abbrev == "" {
			return fragment, nil
		}
		return fmt.Sprintf("%s:%s", abbrev, fragment), nil
	}
	return "", fmt.Errorf("declaration of URI(%s) not found in the schemaDefinition", baseURI)
}

// from a given adjacency list, return a list of root-nodes which will be used
// to generate string forms of the nodes to be written.
func GetRootNodes(triples []*parser.Triple) (rootNodes []*parser.Node) {

	// In a disjoint set, indices with root nodes will point to nil
	// that means, if disjointSet[node] is nil, the node has no parent
	// and it is one of the root nodes.
	var parent map[*parser.Node]*parser.Node
	parent = DisjointSet(triples)

	for node := range parent {
		if parent[node] == nil {
			rootNodes = append(rootNodes, node)
		}
	}
	return rootNodes
}

// returns the triples that are not associated with tags of schemaName "rdf".
func getRestTriples(triples []*parser.Triple) (restTriples []*parser.Triple) {
	rdfTypeURI := parser.RDFNS + "type"
	rdfNodeIDURI := parser.RDFNS + "nodeID"
	for _, triple := range triples {
		if !any(triple.Predicate.ID, []string{rdfNodeIDURI, rdfTypeURI}) {
			restTriples = append(restTriples, triple)
		}
	}
	return restTriples
}
