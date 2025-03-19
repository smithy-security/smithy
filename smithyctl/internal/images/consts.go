package images

const (
	// DefaultNamespace is the context path under which all component images
	// will be available in the container registry
	DefaultNamespace = "smithy-security/images"
	// DefaultRegistry is registry to be used for all the images built by the
	// system
	DefaultRegistry = "ghcr.io"
)

// DefaultLabels are going to be added to every container built by the system
var DefaultLabels = map[string]string{
	"org.opencontainers.image.source": "https://github.com/smithy-security/smithy",
}
