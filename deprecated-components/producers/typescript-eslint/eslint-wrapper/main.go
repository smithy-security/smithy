package main

import (
	"errors"
	"flag"
	"log"
	"os"
	"os/exec"
)

const (
	// ConfigPath is where Dockerfile puts the default configuration for eslint.
	ConfigPath = "/home/node/workspace/eslintrc.js"
	// EsLintBinPath is where the Dockerfile puts the eslint binary by default.
	EsLintBinPath = "/home/node/workspace/node_modules/.bin/eslint"
)

func main() {
	var eslintRC, target string

	// call eslint with the correct flags, optionally write an eslint config file if supplied, otherwise leave the default.
	//  exit with eslint exitcode if  eslint's exitcode is anything other than 1
	flag.StringVar(&eslintRC, "c", "", "the contents of eslintrc.js")
	flag.StringVar(&target, "t", "", "the target to scan")
	flag.Parse()

	if eslintRC != "" {
		log.Println("Config file supplied, overwriting", ConfigPath)
		if err := os.WriteFile(ConfigPath, []byte(eslintRC), 0o600); err != nil {
			log.Fatalf("could not write file: %s", err)
		}
	}

	out, err := exec.Command(EsLintBinPath,
		"--quiet",
		"-f",
		"json",
		"--no-eslintrc",
		"-o",
		"$(workspaces.scratch.path)/out.json",
		"--exit-on-fatal-error",
		"-c", ConfigPath, target).CombinedOutput()

	log.Println("Executing eslint as such:", EsLintBinPath,
		"--quiet",
		"-f",
		"json",
		"-o",
		"$(workspaces.scratch.path)/out.json",
		"--exit-on-fatal-error",
		"-c", ConfigPath, target)
	log.Println("eslint out was", string(out))
	var exitcode *exec.ExitError
	if errors.As(err, &exitcode) {
		if exitcode.ExitCode() != 1 && exitcode.ExitCode() != 2 {
			log.Println("exit code was not 1 or 2 this means that we had a misc err:", err)
			os.Exit(exitcode.ExitCode())
		}
	}
	eslintOut, err := os.ReadFile("$(workspaces.scratch.path)/out.json")
	if err != nil {
		log.Println("could not read eslint output, err:")
		panic(err)
	}
	log.Println(string(eslintOut), "successfully ran eslint, exiting")
}
