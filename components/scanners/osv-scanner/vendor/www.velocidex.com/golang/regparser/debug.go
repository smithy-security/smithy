package regparser

import (
	"fmt"
	"os"
	"strings"
)

var debugOutput bool

func init() {
	for _, x := range os.Environ() {
		if strings.HasPrefix(x, "REGPARSER_DEBUG=") {
			debugOutput = true
			break
		}
	}
}

func DebugPrint(fmt_str string, v ...interface{}) {
	if debugOutput {
		fmt.Printf(fmt_str, v...)
	}
}
