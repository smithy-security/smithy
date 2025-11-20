package languages

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/go-errors/errors"
	"github.com/pelletier/go-toml/v2"
	"golang.org/x/mod/modfile"
)

// Dependency is a version of a package listed in a file
type Dependency struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// DependencyReport holds the parsed results for a dependency file.
type DependencyReport struct {
	Language
	LanguageVersion      string
	LanguageVersionLine  int
	Dependencies         map[Dependency][]int
	IndirectDependencies map[Dependency][]int
	TestDependencies     map[Dependency][]int
	DevDependencies      map[Dependency][]int
}

// DependencyAnalyser is a component that can analyse a dependency file and
// extract all the package and language information from it along with the lines
type DependencyAnalyser interface {
	Analyse(filePath string) (DependencyReport, error)
}

// GoModAnalyser analyses a go.mod file and extracts a list of all the
// dependencies
type GoModAnalyser struct{}

// Analyse will analyse the
func (g GoModAnalyser) Analyse(filePath string) (depRep DependencyReport, err error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return depRep, errors.Errorf("failed to read go.mod: %w", err)
	}

	modFile, err := modfile.Parse(filePath, data, nil)
	if err != nil {
		return depRep, errors.Errorf("failed to parse go.mod: %w", err)
	}

	if modFile.Go != nil {
		depRep.LanguageVersion = modFile.Go.Version
	} else {
		return depRep, errors.New("go.mod file has no language version in it")
	}

	depRep.Dependencies = make(map[Dependency][]int)
	depRep.IndirectDependencies = make(map[Dependency][]int)
	for _, req := range modFile.Require {
		dep := Dependency{
			Name:    req.Mod.Path,
			Version: req.Mod.Version,
		}
		line := req.Syntax.Start.Line

		if req.Indirect {
			depRep.IndirectDependencies[dep] = append(depRep.IndirectDependencies[dep], line)
		} else {
			depRep.Dependencies[dep] = append(depRep.Dependencies[dep], line)
		}
	}

	depRep.Language = GOLANG

	dataBuffer := bytes.NewBuffer(data)
	scanner := bufio.NewScanner(dataBuffer)
	lineNum := 0
	expectedGoVersionLine := fmt.Sprintf("go %s", depRep.LanguageVersion)
	for scanner.Scan() {
		lineNum++
		if scanner.Text() == expectedGoVersionLine {
			depRep.LanguageVersionLine = lineNum
			break
		}
	}

	return depRep, nil
}

// CargoAnalyser is tasked with analysing a Cargo file and extracting
// dependencies from it
type CargoAnalyser struct{}

type cargoToml struct {
	Dependencies    map[string]any `toml:"dependencies"`
	DevDependencies map[string]any `toml:"dev-dependencies"`
}

// Analyse handles Rust dependencies in Cargo.toml.
func (c *CargoAnalyser) Analyse(filePath string) (DependencyReport, error) {
	var cargo cargoToml
	data, err := os.ReadFile(filePath)
	if err != nil {
		return DependencyReport{}, errors.Errorf("could not read file: %w", err)
	}

	if err := toml.Unmarshal(data, &cargo); err != nil {
		return DependencyReport{}, errors.Errorf("failed to unmarshal Cargo.toml: %w", err)
	}

	file, err := os.Open(filePath)
	if err != nil {
		return DependencyReport{}, errors.Errorf("failed to read Cargo.toml: %w", err)
	}

	var (
		depRep = DependencyReport{
			Dependencies:    make(map[Dependency][]int),
			DevDependencies: make(map[Dependency][]int),
		}
		scanningDependencies    = false
		scanningDevDependencies = false
	)

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.Trim(scanner.Text(), " ")

		switch {
		case len(line) == 0:
			continue
		case strings.HasPrefix(line, "#"):
			continue
		case line == "[dependencies]":
			scanningDependencies = true
			scanningDevDependencies = false
		case line == "[dev-dependencies]":
			scanningDependencies = false
			scanningDevDependencies = true
		case strings.HasPrefix(line, "["):
			scanningDependencies = false
			scanningDevDependencies = false
		case !scanningDependencies && !scanningDevDependencies:
			continue
		default:
			splits := strings.SplitN(line, " = ", 2)
			var (
				pkgName       = splits[0]
				pkgVersion    string
				rawPkgVersion any
			)

			if scanningDependencies {
				rawPkgVersion = cargo.Dependencies[pkgName]
			} else {
				rawPkgVersion = cargo.DevDependencies[pkgName]
			}

			switch v := rawPkgVersion.(type) {
			case string:
				pkgVersion = v
			case map[string]any:
				var (
					getStr = func(m map[string]any, key string) (string, bool) {
						a, ok := m[key]
						if !ok {
							return "", false
						}

						s, ok := a.(string)
						if !ok {
							return "", false
						}

						return s, true
					}
					pkgVersionStr string
					ok            bool
				)

				if pkgVersionStr, ok = getStr(v, "version"); ok {
					pkgVersion = pkgVersionStr
				} else if pkgVersionStr, ok = getStr(v, "tag"); ok {
					pkgVersion = pkgVersionStr
				} else if pkgVersionStr, ok = getStr(v, "rev"); ok {
					pkgVersion = pkgVersionStr
				} else if pkgVersionStr, ok = getStr(v, "branch"); ok {
					pkgVersion = pkgVersionStr
				}
			}

			dep := Dependency{
				Name:    pkgName,
				Version: pkgVersion,
			}

			if scanningDependencies {
				depRep.Dependencies[dep] = append(depRep.Dependencies[dep], lineNum)
			} else {
				depRep.DevDependencies[dep] = append(depRep.DevDependencies[dep], lineNum)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return DependencyReport{}, errors.Errorf("error reading file: %w", err)
	}

	depRep.Language = RUST

	return depRep, nil
}

// JSPackageAnalyser will analyse a package.lock and will return a map of the
// packages and their lines in a JavaScript/TypeScript dependency file
type JSPackageAnalyser struct{}

type packageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// Analyse handles JavaScript/TypeScript dependencies in package.json.
func (j JSPackageAnalyser) Analyse(filePath string) (DependencyReport, error) {
	var packages packageJSON
	data, err := os.ReadFile(filePath)
	if err != nil {
		return DependencyReport{}, errors.Errorf("could not read file: %w", err)
	}

	if err := json.Unmarshal(data, &packages); err != nil {
		return DependencyReport{}, errors.Errorf("failed to unmarshal packages.json: %w", err)
	}

	file, err := os.Open(filePath)
	if err != nil {
		return DependencyReport{}, errors.Errorf("failed to read packages.json: %w", err)
	}

	var (
		depRep = DependencyReport{
			Dependencies:    make(map[Dependency][]int),
			DevDependencies: make(map[Dependency][]int),
		}
		scanningDependencies    = false
		scanningDevDependencies = false
	)

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.Trim(scanner.Text(), " ")

		switch {
		case len(line) == 0:
			continue
		case strings.Contains(line, "dependencies"):
			scanningDependencies = true
			scanningDevDependencies = false
		case strings.Contains(line, "devDependencies"):
			scanningDependencies = false
			scanningDevDependencies = true
		case strings.Contains(line, "}"):
			scanningDependencies = false
			scanningDevDependencies = false
		case !scanningDependencies && !scanningDevDependencies:
			continue
		default:
			pkgName := strings.Trim(strings.SplitN(line, ":", 2)[0], " \"\\")
			var pkgVersion string

			if scanningDependencies {
				pkgVersion = packages.Dependencies[pkgName]
			} else {
				pkgVersion = packages.DevDependencies[pkgName]
			}

			dep := Dependency{
				Name:    pkgName,
				Version: pkgVersion,
			}

			if scanningDependencies {
				depRep.Dependencies[dep] = append(depRep.Dependencies[dep], lineNum)
			} else {
				depRep.DevDependencies[dep] = append(depRep.DevDependencies[dep], lineNum)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return DependencyReport{}, errors.Errorf("error reading file: %w", err)
	}

	depRep.Language = JAVASCRIPT

	return depRep, nil
}

// JSPackageLockAnalyser will analyse a package-lock.json file and return
// information about where all the dependencies are listed in the file
type JSPackageLockAnalyser struct{}

func (j JSPackageLockAnalyser) Analyse(filePath string) (DependencyReport, error) {
	packageLockFp, err := os.OpenFile(filePath, os.O_RDONLY, 0666)
	if err != nil {
		return DependencyReport{}, errors.Errorf("%s: could not read file: %w", filePath, err)
	}

	var (
		depRep = DependencyReport{
			Dependencies: make(map[Dependency][]int),
		}
		scanningDependencyVersion = false
		packageName               string
		version                   string
	)

	lineNum := 0
	scanner := bufio.NewScanner(packageLockFp)
	for scanner.Scan() {
		lineNum++
		line := strings.Trim(scanner.Text(), " \"")
		if strings.HasPrefix(line, "node_modules") {
			packageName = strings.Trim(line, " :\"{")
			packageNameComponents := strings.Split(packageName, "node_modules/")
			packageName = packageNameComponents[len(packageNameComponents)-1]
			scanningDependencyVersion = true
		} else if scanningDependencyVersion {
			version = strings.Split(line, ":")[1]
			version = strings.Trim(version, " ,\"")
			dep := Dependency{
				Name:    packageName,
				Version: version,
			}
			depRep.Dependencies[dep] = append(depRep.Dependencies[dep], lineNum)
			scanningDependencyVersion = false
		}
	}

	depRep.Language = JAVASCRIPT

	return depRep, nil
}

// RebarAnalyser will analyse a rebar.config file and its dependencies
type RebarAnalyser struct{}

// Analyse will parse the rebar.config file of an Erlang project and will
// return a report with all the dependencies and the lines where they are
// located.
func (r RebarAnalyser) Analyse(filePath string) (DependencyReport, error) {
	versionRegex := regexp.MustCompile("^[0-9]+.[0-9]+.[0-9]+$")

	file, err := os.Open(filePath)
	if err != nil {
		return DependencyReport{}, errors.Errorf("could not read file: %w", err)
	}

	var (
		depRep = DependencyReport{
			Dependencies: make(map[Dependency][]int),
		}
		scanningDependencies = false
	)

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.Trim(scanner.Text(), " ")

		switch {
		case len(line) == 0 || strings.HasPrefix(line, "%%"):
			continue
		case strings.Contains(line, "{deps, ["):
			scanningDependencies = true
		case strings.Contains(line, "]}.") && scanningDependencies:
			goto finishParsing
		case !scanningDependencies:
			continue
		default:
			var (
				pkg           = strings.SplitN(line, ",", 2)
				pkgName       = strings.Trim(pkg[0], "{")
				rawPkgVersion = strings.Trim(pkg[1], "}, \"\\")
				pkgVersion    = ""
			)

			if len(rawPkgVersion) > 0 && versionRegex.MatchString(rawPkgVersion) {
				pkgVersion = rawPkgVersion
			}

			dep := Dependency{
				Name:    pkgName,
				Version: pkgVersion,
			}
			depRep.Dependencies[dep] = append(depRep.Dependencies[dep], lineNum)
		}
	}

finishParsing:
	if err := scanner.Err(); err != nil {
		return DependencyReport{}, errors.Errorf("error reading file: %w", err)
	}

	depRep.Language = ERLANG

	return depRep, nil
}

// ElixirLockAnalyser analyses a mix.lock file to return a report with all the
// dependencies listed in the file
type ElixirLockAnalyser struct{}

// Analyse will parse the rebar.config file of an Erlang project and will
// return a report with all the dependencies and the lines where they are
// located.
func (e ElixirLockAnalyser) Analyse(filePath string) (DependencyReport, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return DependencyReport{}, errors.Errorf("could not read file: %w", err)
	}

	var (
		depRep = DependencyReport{
			Dependencies: make(map[Dependency][]int),
		}
		scanningDependencies = false
	)

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.Trim(scanner.Text(), " ")

		switch {
		case len(line) == 0:
			continue
		case strings.Contains(line, "%{"):
			scanningDependencies = true
		case line == "}" && scanningDependencies:
			goto finishParsing
		case !scanningDependencies:
			continue
		default:
			var (
				pkg        = strings.SplitN(line, ":", 2)
				pkgName    = strings.Trim(pkg[0], " \"")
				pkgInfo    = strings.SplitN(pkg[1], ",", 4)
				pkgVersion = strings.Trim(pkgInfo[2], " \"")
			)

			dep := Dependency{
				Name:    pkgName,
				Version: pkgVersion,
			}
			depRep.Dependencies[dep] = append(depRep.Dependencies[dep], lineNum)
		}
	}

finishParsing:
	if err := scanner.Err(); err != nil {
		return DependencyReport{}, errors.Errorf("error reading file: %w", err)
	}

	depRep.Language = ELIXIR

	return depRep, nil
}
