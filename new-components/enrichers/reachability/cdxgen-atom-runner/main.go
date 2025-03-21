package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"path"
	"strings"

	"github.com/go-errors/errors"
	langs "github.com/smithy-security/pkg/detect-repo-languages"
)

var (
	sourceLocation  string
	scratchLocation string
)

type SupportedLanguage int

const (
	C SupportedLanguage = iota
	Java
	Javascript
	Typescript
	PHP
	Python
	Ruby
)

var (
	langName = map[SupportedLanguage]string{
		Java:       "java",
		Javascript: "javascript",
		Typescript: "javascript",
		PHP:        "php",
		Python:     "python",
		Ruby:       "ruby",
	}
	toLang = map[string]SupportedLanguage{
		"java":                 Java,
		"java properties":      Java,
		"java server pages":    Java,
		"java template engine": Java,
		"javascript":           Javascript,
		"javascript+erb":       Javascript,
		"typescript":           Typescript,
		"php":                  PHP,
		"python":               Python,
		"python console":       Python,
		"python traceback":     Python,
		"ruby":                 Ruby,
	}
)

func main() {

	flag.StringVar(&sourceLocation, "source-location", "", "location of source code")
	flag.StringVar(&scratchLocation, "scratch-location", "", "location of source code")
	flag.Parse()

	if sourceLocation == "" {
		log.Fatal("source-location cannot be empty")
	}

	if scratchLocation == "" {
		log.Fatal("scratch-location cannot be empty")
	}

	slog.Info("running codeql against source code at", slog.String("source", sourceLocation), "putting results at", slog.String("scratch", scratchLocation))
	langs, err := detectLanguages(sourceLocation)
	if err != nil {
		log.Fatalf("could not detect languages, err: %s", err)
	}
	slog.Info("found ", slog.String("langs", strings.Join(langs, ",")))
	for _, l := range langs {
		lang, ok := toLang[l]
		if !ok {
			slog.Info("is not supported by codeql, skipping", slog.String("lang", l))
			continue
		}
		slog.Info("preparing codeql database for ", slog.String("lang", l))
		sbomFile, err := generateSBOM(lang)
		if err != nil {
			log.Fatalf("could not prepare codeql database for language %s, err: %s", langName[lang], err)
		}
		slog.Info("running detection for ", slog.String("lang", l))

		if err := generateReachableSlices(lang, sbomFile); err != nil {
			log.Fatalf("could not run codeql database analyze for language %s, err: %s", langName[lang], err)
		}
	}
}

func detectLanguages(sourceLocation string) ([]string, error) {
	file, err := os.Stat(sourceLocation)
	if err != nil {
		return nil, errors.Errorf("could not read source code from path '%s', err: '%s'", sourceLocation, err)
	}
	if !file.IsDir() {
		return nil, errors.Errorf("could not read source code from path '%s', it's not a directory", sourceLocation)
	}
	return langs.Detect(sourceLocation)
}

func generateSBOM(lang SupportedLanguage) (string, error) {
	slog.Info("running", slog.String("command",
		fmt.Sprintf("node /opt/cdxgen/bin/cdxgen.js -t %s --deep -r --feature-flags safe-pip-install -p -o %s	%s --spec-version 1.5",
			langName[lang],
			path.Join(scratchLocation, "bom.json"),
			sourceLocation)))
	outfileLoc := path.Join(scratchLocation, fmt.Sprintf("%s.bom.json", langName[lang]))
	command := exec.Command("node",
		"/opt/cdxgen/bin/cdxgen.js",
		"-t", langName[lang],
		"--deep",
		"-r",
		"--feature-flags safe-pip-install",
		"-p",
		"-o", outfileLoc,
		sourceLocation,
		"--spec-version", "1.5")
	command.Env = append(command.Env, "NPM_INSTALL_ARGS='--force --ignore-scripts --package-lock --legacy-peer-deps'")
	out, err := command.CombinedOutput()
	if err != nil {
		return "", errors.Errorf("could not generate SBOM for lang %s, could not run command, output: %s err: %w", langName[lang], string(out), err)
	}
	slog.Info("successfully generated SBOM for ", slog.String("language", langName[lang]), slog.String("output", string(out)))
	return outfileLoc, nil
}

func generateReachableSlices(lang SupportedLanguage, bomFileLoc string) error {
	bomDir := path.Dir(bomFileLoc)
	targetFilepath := path.Join(bomDir, "bom.json")
	if err := os.Rename(bomFileLoc, targetFilepath); err != nil {
		return errors.Errorf("could not rename bom file %s to %s, err: %w", bomFileLoc, targetFilepath, err)
	}
	atomOutput := path.Join(sourceLocation, fmt.Sprintf("%s.app.atom", langName[lang]))
	atomSlices := path.Join(scratchLocation, fmt.Sprintf("%s.reachables.json", langName[lang]))
	slog.Info("running", slog.String("command",
		fmt.Sprintf("atom reachables -o %s -s %s -l %s %s",
			atomOutput, atomSlices, langName[lang], sourceLocation,
		)))
	command := exec.Command("/opt/bin/atom",
		"reachables",
		"-o", atomOutput,
		"-s", atomSlices,
		"-l", langName[lang],
		sourceLocation,
	)
	out, err := command.CombinedOutput()
	if err != nil {
		return errors.Errorf("could not generate reachable slices, could not run command, output: %s err: %w", string(out), err)
	}
	slog.Info("successfully generated reachable slices for ", slog.String("language", langName[lang]), slog.String("output", string(out)))
	slog.Info("output", slog.String("filename", atomOutput), slog.String("slices", atomSlices))
	return nil
}
