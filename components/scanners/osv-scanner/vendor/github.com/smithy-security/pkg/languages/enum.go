package languages

// Language is an enum for languages that our ecosystem can process
type Language string

const (
	RUST       Language = "Rust"
	GOLANG     Language = "Golang"
	PYTHON     Language = "Python"
	JAVA       Language = "Java"
	KOTLIN     Language = "Kotlin"
	ERLANG     Language = "Erlang"
	ELIXIR     Language = "Elixir"
	JAVASCRIPT Language = "Javascript"
	TYPESCRIPT Language = "Typescript"
)

// String returns the string representation of the language
func (l Language) String() string {
	return string(l)
}
