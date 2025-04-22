package dtrack

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/mod/semver"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultTimeout   = 10 * time.Second
	DefaultUserAgent = "github.com/DependencyTrack/client-go"
)

type contextKey string

type Client struct {
	httpClient *http.Client
	baseURL    *url.URL
	userAgent  string
	debug      bool
	about      About

	About             AboutService
	Analysis          AnalysisService
	BOM               BOMService
	Component         ComponentService
	Config            ConfigService
	Finding           FindingService
	Event             EventService
	License           LicenseService
	Metrics           MetricsService
	OIDC              OIDCService
	Permission        PermissionService
	Policy            PolicyService
	PolicyCondition   PolicyConditionService
	PolicyViolation   PolicyViolationService
	Project           ProjectService
	ProjectProperty   ProjectPropertyService
	Repository        RepositoryService
	Team              TeamService
	User              UserService
	VEX               VEXService
	ViolationAnalysis ViolationAnalysisService
	Vulnerability     VulnerabilityService
}

func NewClient(baseURL string, options ...ClientOption) (*Client, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("no api base url provided")
	}

	u, err := url.ParseRequestURI(baseURL)
	if err != nil {
		return nil, err
	}

	client := Client{
		baseURL: u,
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		userAgent: DefaultUserAgent,
		debug:     false,
	}

	for _, option := range options {
		if optionErr := option(&client); optionErr != nil {
			return nil, optionErr
		}
	}

	client.About = AboutService{client: &client}
	client.Analysis = AnalysisService{client: &client}
	client.BOM = BOMService{client: &client}
	client.Component = ComponentService{client: &client}
	client.Config = ConfigService{client: &client}
	client.Finding = FindingService{client: &client}
	client.Event = EventService{client: &client}
	client.License = LicenseService{client: &client}
	client.Metrics = MetricsService{client: &client}
	client.OIDC = OIDCService{client: &client}
	client.Permission = PermissionService{client: &client}
	client.Policy = PolicyService{client: &client}
	client.PolicyCondition = PolicyConditionService{client: &client}
	client.PolicyViolation = PolicyViolationService{client: &client}
	client.Project = ProjectService{client: &client}
	client.ProjectProperty = ProjectPropertyService{client: &client}
	client.Repository = RepositoryService{client: &client}
	client.Team = TeamService{client: &client}
	client.User = UserService{client: &client}
	client.VEX = VEXService{client: &client}
	client.ViolationAnalysis = ViolationAnalysisService{client: &client}
	client.Vulnerability = VulnerabilityService{client: &client}

	client.about, err = client.About.Get(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch version information: %w", err)
	}

	return &client, nil
}

// BaseURL provides a copy of the Dependency-Track base URL.
func (c Client) BaseURL() *url.URL {
	u := *c.baseURL
	return &u
}

func (c Client) isServerVersionAtLeast(targetVersion string) bool {
	// semver requires versions to be prefixed with "v",
	// and doesn't support "-SNAPSHOT" suffixes.
	targetVersionNormalized := fmt.Sprintf("v%s", targetVersion)
	actualVersionNormalized := fmt.Sprintf("v%s", strings.TrimSuffix(c.about.Version, "-SNAPSHOT"))
	return semver.Compare(targetVersionNormalized, actualVersionNormalized) <= 0
}

func (c Client) assertServerVersionAtLeast(targetVersion string) error {
	if !c.isServerVersionAtLeast(targetVersion) {
		return fmt.Errorf("server version must be at least %s, but is %s", targetVersion, c.about.Version)
	}

	return nil
}

func (c Client) newRequest(ctx context.Context, method, path string, options ...requestOption) (*http.Request, error) {
	u, err := c.baseURL.Parse(path)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	for _, option := range options {
		if err = option(req); err != nil {
			return nil, err
		}
	}

	return req, nil
}

type requestOption func(*http.Request) error

func withParams(params map[string]string) requestOption {
	return func(req *http.Request) error {
		if len(params) == 0 {
			return nil
		}

		query := req.URL.Query()

		for pk, pv := range params {
			query.Add(pk, pv)
		}

		req.URL.RawQuery = query.Encode()

		return nil
	}
}

func withPathParams(params map[string]string) requestOption {
	return func(req *http.Request) error {
		if len(params) == 0 {
			return nil
		}

		for k, v := range params {
			req.URL.Path = strings.Replace(req.URL.Path, fmt.Sprintf("{%s}", k), v, -1)
		}
		return nil
	}
}

func withBody(body interface{}) requestOption {
	return func(req *http.Request) error {
		if body == nil {
			return nil
		}

		var (
			contentType string
			bodyBuf     io.ReadWriter
		)

		switch body := body.(type) {
		case url.Values:
			bodyBuf = bytes.NewBufferString("")
			if _, err := fmt.Fprint(bodyBuf, body.Encode()); err != nil {
				return err
			}
			contentType = "application/x-www-form-urlencoded"
		case string:
			bodyBuf = new(bytes.Buffer)
			_, err := io.WriteString(bodyBuf, body)
			contentType = "text/plain"
			if err != nil {
				return err
			}
		default:
			bodyBuf = new(bytes.Buffer)
			if err := json.NewEncoder(bodyBuf).Encode(body); err != nil {
				return err
			}
			contentType = "application/json"
		}

		req.Body = io.NopCloser(bodyBuf)
		req.Header.Set("Content-Type", contentType)

		return nil
	}
}

func withMultiPart(body url.Values) requestOption {
	return func(req *http.Request) error {
		if body == nil {
			return nil
		}

		var bodyBuf bytes.Buffer
		multipartWriter := multipart.NewWriter(&bodyBuf)
		for key, valueList := range body {
			for _, value := range valueList {
				fw, _ := multipartWriter.CreateFormField(key)
				_, _ = fw.Write([]byte(value))
			}
		}

		_ = multipartWriter.Close()
		req.Body = io.NopCloser(&bodyBuf)
		req.Header.Set("Content-Type", multipartWriter.FormDataContentType())

		return nil
	}
}

type Page[T any] struct {
	Items      []T // Items on this page
	TotalCount int // Total number of items
}

type PageOptions struct {
	Offset     int // Offset of the elements to return
	PageNumber int // Page to return
	PageSize   int // Amount of elements to return per page
}

func withPageOptions(po PageOptions) requestOption {
	return func(req *http.Request) error {
		query := req.URL.Query()

		if po.Offset > 0 {
			query.Set("offset", strconv.Itoa(po.Offset))
		} else if po.PageNumber > 0 {
			query.Set("pageNumber", strconv.Itoa(po.PageNumber))
		}

		if po.PageSize > 0 {
			query.Set("pageSize", strconv.Itoa(po.PageSize))
		}

		req.URL.RawQuery = query.Encode()

		return nil
	}
}

func withAcceptContentType(contentType string) requestOption {
	return func(req *http.Request) error {
		req.Header.Set("Accept", contentType)
		return nil
	}
}

func (c Client) doRequest(req *http.Request, v interface{}) (a apiResponse, err error) {
	if c.debug {
		reqDump, _ := httputil.DumpRequestOut(req, true)
		log.Printf("sending request:\n>>>>>>\n%s\n>>>>>>\n", string(reqDump))
	}

	res, err := c.httpClient.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()

	if c.debug {
		resDump, _ := httputil.DumpResponse(res, true)
		log.Printf("received response:\n<<<<<<\n%s\n<<<<<<\n", string(resDump))
	}

	err = checkResponseForError(res)
	if err != nil {
		return
	}

	if v != nil {
		switch vt := v.(type) {
		case *string:
			if content, readErr := io.ReadAll(res.Body); readErr == nil {
				*vt = strings.TrimSpace(string(content))
			} else {
				err = readErr
				return
			}
		default:
			err = json.NewDecoder(res.Body).Decode(v)
			if err != nil {
				return
			}
		}
	}

	a, err = c.newAPIResponse(res)
	return
}

type apiResponse struct {
	*http.Response
	TotalCount int
}

func (c Client) newAPIResponse(res *http.Response) (a apiResponse, err error) {
	a = apiResponse{Response: res}

	totalCount, ok := a.Header["X-Total-Count"]
	if ok && len(totalCount) > 0 {
		totalCountVal, convErr := strconv.Atoi(totalCount[0])
		if convErr != nil {
			err = convErr
			return
		}
		a.TotalCount = totalCountVal
	}

	return
}

type ClientOption func(*Client) error

// WithDebug toggles the debug mode.
// When enabled, HTTP requests and responses will be logged to stderr.
// DO NOT USE IN PRODUCTION, authorization headers are not cleared!
func WithDebug(debug bool) ClientOption {
	return func(c *Client) error {
		c.debug = debug
		return nil
	}
}

// WithUserAgent overrides the default user agent.
func WithUserAgent(userAgent string) ClientOption {
	return func(c *Client) error {
		c.userAgent = userAgent
		return nil
	}
}

// WithTimeout overrides the default timeout.
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) error {
		c.httpClient.Timeout = timeout
		return nil
	}
}

// WithMTLS configures the http client to use client certificates
func WithMTLS(caCertFile string, clientCertFile string, clientKeyFile string) ClientOption {
	return func(c *Client) error {
		caCert, err := os.ReadFile(caCertFile)
		if err != nil {
			return fmt.Errorf("failed to load ca cert file: %w", err)
		}

		certPool, _ := x509.SystemCertPool()
		if certPool == nil {
			certPool = x509.NewCertPool()
		}

		certPool.AppendCertsFromPEM(caCert)

		keyPair, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
		if err != nil {
			return fmt.Errorf("failed to load client key pair: %w", err)
		}

		tlsConfig := &tls.Config{
			RootCAs:      certPool,
			Certificates: []tls.Certificate{keyPair},
			MinVersion:   tls.VersionTLS12,
		}

		if c.httpClient.Transport == nil {
			httpTransport := http.DefaultTransport.(*http.Transport)
			httpTransport.TLSClientConfig = tlsConfig
			c.httpClient.Transport = httpTransport
			return nil
		}

		httpTransport, ok := c.httpClient.Transport.(*http.Transport)
		if ok {
			httpTransport.TLSClientConfig = tlsConfig
			return nil
		}

		authTransport, ok := c.httpClient.Transport.(*authHeaderTransport)
		if ok {
			httpTransport = authTransport.transport.(*http.Transport)
			httpTransport.TLSClientConfig = tlsConfig
			return nil
		}

		return errors.New("could not set tls options")
	}
}

// WithHttpClient overrides the default HttpClient.
func WithHttpClient(client *http.Client) ClientOption {
	return func(c *Client) error {
		c.httpClient = client
		return nil
	}
}
