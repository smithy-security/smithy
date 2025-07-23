package mock

type MockClient struct {
	StopCallBack         func() error
	GetPDFOfPageCallBack func(string, string) ([]byte, error)
}

// NewClient returns an actual github client
func NewMockClient() (MockClient, error) {
	return MockClient{}, nil
}

func (c MockClient) Stop() error {
	return c.StopCallBack()
}

func (c MockClient) GetPDFOfPage(page, storePath string) ([]byte, error) {
	return c.GetPDFOfPageCallBack(page, storePath)
}
