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
	Csharp SupportedLanguage = iota
	Go
	Java
	Kotlin
	Javascript
	Typescript
	Python
	Ruby
	Swift

	aggregateDBsDir = "codeql-dbs"
)

var (
	langName = map[SupportedLanguage]string{
		Csharp:     "csharp",
		Go:         "go",
		Java:       "java",
		Kotlin:     "kotlin",
		Javascript: "javascript",
		Typescript: "javascript",
		Python:     "python",
		Ruby:       "ruby",
		Swift:      "swift",
	}
	toLang = map[string]SupportedLanguage{
		"c#":                   Csharp,
		"go":                   Go,
		"go checksums":         Go,
		"go module":            Go,
		"go workspace":         Go,
		"java":                 Java,
		"java properties":      Java,
		"java server pages":    Java,
		"java template engine": Java,
		"kotlin":               Kotlin,
		"javascript":           Javascript,
		"javascript+erb":       Javascript,
		"typescript":           Typescript,
		"python":               Python,
		"python console":       Python,
		"python traceback":     Python,
		"ruby":                 Ruby,
		"swift":                Swift,
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
		if err := prepareDatabase(lang); err != nil {
			log.Fatalf("could not prepare codeql database for language %s, err: %s", langName[lang], err)
		}
		slog.Info("running detection for ", slog.String("lang", l))

		if err := runDetection(lang); err != nil {
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

func prepareDatabase(lang SupportedLanguage) error {
	dbLoc := path.Join(scratchLocation, aggregateDBsDir)
	slog.Info("checking if exists", slog.String("database dir", dbLoc))
	_, err := os.Stat(dbLoc)
	if errors.Is(err, os.ErrNotExist) {
		slog.Info("does not exist, creating", slog.String("database dir", dbLoc))

		if err := os.MkdirAll(dbLoc, os.ModePerm); err != nil {
			return errors.Errorf("could not create temporary databases directory, err: %w", err)
		}
	} else if err != nil {
		return errors.Errorf("could not check if the aggregate database directory exists, err: %w", err)
	}
	buildMode := "none"
	if lang == Go {
		buildMode = "autobuild"
	}
	slog.Info("running", slog.String("command", fmt.Sprintf("/codeql/codeql database create %s --source-root %s --db-cluster --language %s --threads 10 --build-mode %s --overwrite",
		path.Join(dbLoc, langName[lang]), sourceLocation, langName[lang], buildMode)))

	command := exec.Command("/codeql/codeql", "database", "create",
		path.Join(dbLoc, langName[lang]),
		"--source-root", sourceLocation,
		"--db-cluster",
		"--language", langName[lang],
		"--threads", "10",
		"--build-mode", buildMode,
		"--overwrite")

	out, err := command.CombinedOutput()
	if err != nil {
		return errors.Errorf("could not prepare database for lang %s, could not run command, output: %s err: %w", langName[lang], string(out), err)
	}
	slog.Info("successfully finished running codeql database create for ", slog.String("language", langName[lang]), slog.String("output", string(out)))
	return nil
}

func finalizeDB(lang SupportedLanguage) error {
	slog.Info("finalizing ", slog.String("db", langName[lang]))
	dbLoc := path.Join(scratchLocation, aggregateDBsDir)

	slog.Info("running", slog.String("command", fmt.Sprintf("/codeql/codeql database finalize %s", path.Join(dbLoc, langName[lang]))))
	command := exec.Command("/codeql/codeql", "database", "finalize", path.Join(dbLoc, langName[lang]))
	out, err := command.CombinedOutput()
	if err != nil {
		return errors.Errorf("could not finalize database, could not run command, output: %s err: %w", string(out), err)
	}
	slog.Info("successfully finalized codeql database for ", slog.String("language", langName[lang]), slog.String("output", string(out)))
	return nil
}

func runDetection(lang SupportedLanguage) error {
	dbLoc := path.Join(scratchLocation, aggregateDBsDir)
	slog.Info("running", slog.String("command", fmt.Sprintf("/codeql/codeql database analyze %s %s --format sarif-latest --output %s", path.Join(dbLoc, langName[lang]),
		fmt.Sprintf("codeql/%s-queries", langName[lang]), path.Join(scratchLocation, fmt.Sprintf("out.%s.sarif.json", langName[lang])))))

	command := exec.Command("/codeql/codeql", "database", "analyze",
		path.Join(dbLoc, langName[lang], langName[lang]),
		fmt.Sprintf("codeql/%s-queries", langName[lang]),
		"--format", "sarif-latest",
		"--output", path.Join(scratchLocation, fmt.Sprintf("out.%s.sarif.json", langName[lang])))
	out, err := command.CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "needs to be finalized before running queries") {
			slog.Info("database needs finalizing, calling finalization")
			if err := finalizeDB(lang); err != nil {
				return err
			}
			return runDetection(lang)
		}
		return errors.Errorf("could not analyze database, could not run command, output: %s err: %w", string(out), err)
	}
	slog.Info("successfully finished running codeql database analyze for ", slog.String("language", langName[lang]), slog.String("output", string(out)))
	return nil
}
