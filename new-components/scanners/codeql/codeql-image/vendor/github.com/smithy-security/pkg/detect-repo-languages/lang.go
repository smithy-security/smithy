package repolanguages

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-enry/go-enry/v2"
)

//revive:disable:cyclomatic,cognitive-complexity High complexity score but easy to understand
func Detect(codeDir string) ([]string, error) {
	root, err := filepath.Abs(codeDir)
	if err != nil {
		return nil, err
	}

	_, err = os.Stat(codeDir)
	if os.IsExist(err) {
		return nil, err
	}

	discoveredFiles := map[string][]string{}
	err = filepath.Walk(root, func(path string, f os.FileInfo, err error) error {
		if err != nil {
			return filepath.SkipDir
		}

		isDir := f.IsDir()
		if !isDir && !f.Mode().IsRegular() {
			return nil
		}

		if relativePath, err := filepath.Rel(root, path); err != nil || relativePath == "." {
			return nil
		}

		if enry.IsVendor(path) ||
			enry.IsDotFile(path) ||
			enry.IsDocumentation(path) ||
			enry.IsConfiguration(path) || isDir {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		if enry.IsGenerated(path, content) {
			return nil
		}

		language := enry.GetLanguage(filepath.Base(path), content)
		if language == enry.OtherLanguage {
			return nil
		}

		if enry.GetLanguageType(language) != enry.Programming {
			return nil
		}

		if enry.GetLanguageType(language) != enry.Programming {
			return nil
		}

		discoveredFiles[language] = append(discoveredFiles[language], path)
		return nil
	})

	if err != nil {
		return nil, err
	}

	result := []string{}
	for k := range maps.Keys(discoveredFiles) {
		result = append(result, strings.ToLower(k))
	}
	slices.Sort(result)
	return result, nil
}
