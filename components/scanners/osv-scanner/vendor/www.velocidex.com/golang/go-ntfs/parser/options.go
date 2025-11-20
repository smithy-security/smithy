package parser

const (
	DefaultMaxLinks = 0
)

type Options struct {
	// Include short names in Link analysis
	IncludeShortNames bool

	// Max number of links to retrieve
	MaxLinks int

	// Maximum directory depth to anlayze for paths.
	MaxDirectoryDepth int

	// These path components will be added in front of each link
	// generated.
	PrefixComponents []string
}

func GetDefaultOptions() Options {
	return Options{
		IncludeShortNames: false,
		MaxLinks:          20,
		MaxDirectoryDepth: 20,
	}
}
