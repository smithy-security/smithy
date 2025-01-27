package conf

import (
	"os"

	"github.com/go-errors/errors"
)

const (
	// Environment variables names.
	producerResultsPathEnvVarName = "READ_PATH"
	enrichedResultsPathEnvVarName = "WRITE_PATH"
	atomFilePathEnvVarName        = "ATOM_FILE_PATH"
)

type (
	// Conf contains the application's configuration.
	Conf struct {
		// ProducerResultsPath advertises where to find producer results.
		ProducerResultsPath string
		// EnrichedResultsPath advertises where to put enriched result.
		EnrichedResultsPath string
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
			envVarName: producerResultsPathEnvVarName,
			required:   true,
			dest:       &conf.ProducerResultsPath,
		},
		{
			envVarName: enrichedResultsPathEnvVarName,
			required:   true,
			dest:       &conf.EnrichedResultsPath,
		},
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
			return nil, errors.Errorf("environment variable %s not set but it's required", ev.envVarName)
		}
	}
	return conf, nil
}
