package main

import (
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"

	packageurl "github.com/package-url/packageurl-go"
)

var (
	purl      string
	outputDir string
)

func main() {
	flag.StringVar(&purl, "purl", "", "the purl to transform to a dependency file")
	flag.StringVar(&outputDir, "outDir", "", "where to write output")
	flag.Parse()

	instance, err := packageurl.FromString(purl)
	if err != nil {
		panic(err)
	}
	switch instance.Type {
	case packageurl.TypeGolang:
		createGoPKGs(instance)
	case packageurl.TypeNPM:
		createPackageJSON(instance)
	case packageurl.TypePyPi:
		createRequirementsTxt(instance)
	default:
		log.Fatalf("Package URL type %s is not supported yet, if you would like it to be supported, please open a ticket", instance.Type)
	}
}

func createRequirementsTxt(purl packageurl.PackageURL) {
	requirementsTxt := ""

	switch {
	case purl.Namespace == "":
		requirementsTxt = fmt.Sprintf("%s==%s", purl.Name, purl.Version)
	case purl.Namespace != "" && purl.Name != "" && purl.Version != "":
		requirementsTxt = fmt.Sprintf("%s/%s==%s", purl.Namespace, purl.Name, purl.Version)
	default:
		log.Fatalf("Python package url is %s, this is not supported and it should be, please contact the developers\n", purl.ToString())
	}
	outputPath := filepath.Join(outputDir, "requirements.txt")
	err := os.WriteFile(outputPath, []byte(requirementsTxt), 0o600)
	if err != nil {
		log.Fatalf("Could not create '%s', err: %v", outputPath, err)
	}
}

func createPackageJSON(purl packageurl.PackageURL) {
	namespace, _ := url.QueryUnescape(purl.Namespace)
	name, _ := url.QueryUnescape(purl.Name)
	version, _ := url.QueryUnescape(purl.Version)
	packageJSON := ""

	switch {
	case purl.Namespace == "":
		packageJSON = fmt.Sprintf(`{
		"name": "smithyPurlScanning",
		"version": "0.0.1",
		"description": "this is a dummy package json meant to scan the included dependency",
		"main": "index.js",
		"scripts": {
		  "test": "test"
		},
		"repository": {
		  "type": "git",
		  "url": "example.com"
		},
		"keywords": [
		  "a"
		],
		"author": "foo",
		"license": "ISC",
		"dependencies": {
		  "%s": "%s"
		}
	  }
	  `, name, version)
	case purl.Namespace != "" && purl.Name != "" && purl.Version != "":
		packageJSON = fmt.Sprintf(`{
			"name": "smithyPurlScanning",
			"version": "0.0.1",
			"description": "this is a dummy package json meant to scan the included dependency",
			"main": "index.js",
			"scripts": {
			  "test": "test"
			},
			"repository": {
			  "type": "git",
			  "url": "example.com"
			},
			"keywords": [
			  "a"
			],
			"author": "foo",
			"license": "ISC",
			"dependencies": {
			  "%s-%s": "%s"
			}
		  }
		  `, namespace, name, version)
	default:
		log.Fatalf("NPM package url is %s, this is not supported and it should be, please contact the developers\n", purl.ToString())
	}
	outputPath := filepath.Join(outputDir, "package.json")
	err := os.WriteFile(outputPath, []byte(packageJSON), 0o600)
	if err != nil {
		log.Fatalf("Could not create '%s', err: %v", outputPath, err)
	}
}

func createGoPKGs(purl packageurl.PackageURL) {
	log.Println("Generating Gopkg.lock")
	gopkgToml := "[[constraint]]\n\tname = \"smithy.io/tmp/dep\"\n\tversion = \"1.0.0\"\n"
	gopkgLock := fmt.Sprintf("[[projects]]\n\tname = \"%s/%s\"\n\tpackages = [\".\"]\n\tversion = \"%s\"\n", purl.Namespace, purl.Name, purl.Version)
	outputPath := filepath.Join(outputDir, "Gopkg.toml")
	err := os.WriteFile(outputPath, []byte(gopkgToml), 0o600)
	if err != nil {
		log.Fatalf("Could not create '%s', err: %v", outputPath, err)
	}
	outputPath = filepath.Join(outputDir, "Gopkg.lock")
	err = os.WriteFile(outputPath, []byte(gopkgLock), 0o600)
	if err != nil {
		log.Fatalf("Could not create '%s', err: %v", outputPath, err)
	}
	log.Println("Wrote Gopkg.lock to", outputPath)
	log.Println(gopkgLock)
}
