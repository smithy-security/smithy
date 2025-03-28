package types

// TestSSLFinding represents the output of a single issue in the output array of testssl.sh run.
type TestSSLFinding struct {
	ID       string `json:"id"`
	IP       string `json:"ip"`
	Port     string `json:"port"`
	Severity string `json:"severity"`
	Finding  string `json:"finding"`
}
