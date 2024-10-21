package main

import (
	"log"
	"os"
	"path/filepath"
	"testing"

	packageurl "github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
)

func assertFilesContents(t *testing.T, fileNamesToContents map[string]string, dir string) {
	files, err := os.ReadDir(dir)
	if err != nil {
		log.Fatal(err)
	}
	expected := make([]string, 0, len(fileNamesToContents))

	for k := range fileNamesToContents {
		expected = append(expected, k)
	}
	assert.Equal(t, len(fileNamesToContents), len(files))
	for _, file := range files {
		assert.Contains(t, expected, file.Name())

		dat, _ := os.ReadFile(filepath.Join(dir, file.Name()))
		assert.Equal(t, fileNamesToContents[file.Name()], string(dat))
	}
}

func TestGoPURL(t *testing.T) {
	out, err := os.MkdirTemp("/tmp", "")
	if err != nil {
		log.Fatal(err)
	}
	outputDir = out
	i, _ := packageurl.FromString("pkg:GOLANG/google.golang.org/genproto#/googleapis/api/annotations/")
	createGoPKGs(i)
	expectedContents := map[string]string{
		"Gopkg.toml": "[[constraint]]\n\tname = \"smithy.io/tmp/dep\"\n\tversion = \"1.0.0\"\n",
		"Gopkg.lock": "[[projects]]\n\tname = \"google.golang.org/genproto\"\n\tpackages = [\".\"]\n\tversion = \"\"\n",
	}
	assertFilesContents(t, expectedContents, out)
}

func TestNPMPURL(t *testing.T) {
	out, err := os.MkdirTemp("/tmp", "")
	if err != nil {
		log.Fatal(err)
	}
	outputDir = out
	i, _ := packageurl.FromString("pkg:npm/react/dropzone@14.1.1")
	createPackageJSON(i)
	expectedContents := map[string]string{
		"package.json": "{\n\t\t\t\"name\": \"smithyPurlScanning\",\n\t\t\t\"version\": \"0.0.1\",\n\t\t\t\"description\": \"this is a dummy package json meant to scan the included dependency\",\n\t\t\t\"main\": \"index.js\",\n\t\t\t\"scripts\": {\n\t\t\t  \"test\": \"test\"\n\t\t\t},\n\t\t\t\"repository\": {\n\t\t\t  \"type\": \"git\",\n\t\t\t  \"url\": \"example.com\"\n\t\t\t},\n\t\t\t\"keywords\": [\n\t\t\t  \"a\"\n\t\t\t],\n\t\t\t\"author\": \"foo\",\n\t\t\t\"license\": \"ISC\",\n\t\t\t\"dependencies\": {\n\t\t\t  \"react-dropzone\": \"14.1.1\"\n\t\t\t}\n\t\t  }\n\t\t  ",
	}
	assertFilesContents(t, expectedContents, out)
}

func TestPyPiPurl(t *testing.T) {
	out, err := os.MkdirTemp("/tmp", "")
	if err != nil {
		log.Fatal(err)
	}
	outputDir = out
	i, _ := packageurl.FromString("pkg:PYPI/Django_package@1.11.1.dev1")
	createRequirementsTxt(i)
	expectedContents := map[string]string{
		"requirements.txt": "django-package==1.11.1.dev1",
	}
	assertFilesContents(t, expectedContents, out)
}
