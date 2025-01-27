package wrapper

// Client is the wrapper around s3 sdk
type Client struct {
	UpsertCallback func(string, string, []byte) error
}

// NewMockClient returns a client
func NewMockClient(region string) (Client, error) {
	// create new playwright client
	return Client{}, nil
}

func (c Client) UpsertFile(filename, bucket, _ string, pdfBytes []byte) error {
	return c.UpsertCallback(filename, bucket, pdfBytes)
}
