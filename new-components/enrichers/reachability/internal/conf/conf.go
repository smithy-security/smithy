package conf

import (
	"fmt"
	"os"
)

const (
	// Environment variables names.
	atomFilePathEnvVarName = "ATOM_FILE_PATH"
)

type (
	// Conf contains the application's configuration.
	Conf struct {

		// ATOMFilePath advertises the location of the atom slice file.
		ATOMFilePath string
	}
)

// New returns a new configuration by checking the supplied environment variables.
func New() (*Conf, error) {
	conf := &Conf{}
	for _, ev := range []struct {
		envVarName string
		required   bool
		dest       *string
	}{
		{
			envVarName: atomFilePathEnvVarName,
			required:   true,
			dest:       &conf.ATOMFilePath,
		},
	} {
		var ok bool
		*ev.dest, ok = os.LookupEnv(ev.envVarName)
		switch {
		case (!ok && ev.required) || (ev.required && *ev.dest == ""):
			return nil, fmt.Errorf("environment variable %s not set but it's required", ev.envVarName)
		}
	}
	return conf, nil
}
