// This file is ignored by the go build tool as it ends with the '_test.go' postifx.
// It can be used to export unexported symbols for unit testing while not leaking these to the public API.
package component

// -- START env.go exports --
type EnvLoader envLoader

func WithEnvLoader(loader EnvLoader) envParseOption {
	return withEnvLoader(envLoader(loader))
}

func WithFallbackToDefaultOnError(v bool) envParseOption {
	return withFallbackToDefaultOnError(v)
}

func FromEnvOrDefault[T parseableEnvTypes](envVar string, defaultVal T, opts ...envParseOption) (dest T, err error) {
	return fromEnvOrDefault[T](envVar, defaultVal, opts...)
}

// -- END env.go exports --
