package producers

import (
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	"github.com/package-url/packageurl-go"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/components"

	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type testJ struct {
	Foo string
}

func TestWriteSmithyOutEmpty(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "smithy-test")
	require.NoError(t, err)
	defer require.NoError(t, os.Remove(tmpFile.Name()))

	OutFile = tmpFile.Name()
	Append = false

	err = WriteSmithyOut("smithy-test", nil)
	require.NoError(t, err)

	pBytes, err := os.ReadFile(tmpFile.Name())
	require.NoError(t, err)

	res := v1.LaunchToolResponse{}
	require.NoError(t, proto.Unmarshal(pBytes, &res))

	assert.Equal(t, "smithy-test", res.GetToolName())
	assert.Equal(t, 0, len(res.GetIssues()))
}

func TestWriteSmithyOut(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "smithy-test")
	require.NoError(t, err)
	defer require.NoError(t, os.Remove(tmpFile.Name()))

	baseTime := time.Now().UTC()
	timestamp := baseTime.Format(time.RFC3339)
	require.NoError(t, os.Setenv(components.EnvSmithyStartTime, timestamp))
	require.NoError(t, os.Setenv(components.EnvSmithyScanID, "ab3d3290-cd9f-482c-97dc-ec48bdfcc4de"))

	OutFile = tmpFile.Name()
	Append = false

	err = WriteSmithyOut(
		"smithy-test",
		[]*v1.Issue{
			{
				Target:      path.Join(SourceDir, "foobar"),
				Title:       path.Join(SourceDir, "barfoo"),
				Description: path.Join(SourceDir, "example.yaml"),
				Cve:         "123-321",
			},
		},
	)
	require.NoError(t, err)

	pBytes, err := os.ReadFile(tmpFile.Name())
	require.NoError(t, err)

	res := v1.LaunchToolResponse{}
	require.NoError(t, proto.Unmarshal(pBytes, &res))

	require.Equal(t, "smithy-test", res.GetToolName())
	require.NotEmpty(t, res.GetIssues())
	require.Equal(t, "foobar", res.GetIssues()[0].GetTarget())
	require.Equal(t, "barfoo", res.GetIssues()[0].GetTitle())
	require.Equal(t, "example.yaml", res.GetIssues()[0].GetDescription())
	require.Equal(t, baseTime.Unix(), res.GetScanInfo().GetScanStartTime().GetSeconds())
	require.Equal(t, "ab3d3290-cd9f-482c-97dc-ec48bdfcc4de", res.GetScanInfo().GetScanUuid())
	require.Equal(t, "123-321", res.GetIssues()[0].GetCve())
}

func TestWriteSmithyOutAppend(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "smithy-test")
	require.NoError(t, err)
	defer require.NoError(t, os.Remove(tmpFile.Name()))

	baseTime := time.Now().UTC()
	timestamp := baseTime.Format(time.RFC3339)
	require.NoError(t, os.Setenv(components.EnvSmithyStartTime, timestamp))
	require.NoError(t, os.Setenv(components.EnvSmithyScanID, "ab3d3290-cd9f-482c-97dc-ec48bdfcc4de"))

	OutFile = tmpFile.Name()
	Append = true

	for _, i := range []int{0, 1, 2} {
		err = WriteSmithyOut(
			"smithy-test",
			[]*v1.Issue{
				{
					Target:      fmt.Sprintf("target%d", i),
					Title:       fmt.Sprintf("title%d", i),
					Description: fmt.Sprintf("desc%d", i),
					Cve:         fmt.Sprintf("cve%d", i),
				},
			},
		)
		require.NoError(t, err)
	}

	pBytes, err := os.ReadFile(tmpFile.Name())
	require.NoError(t, err)

	res := v1.LaunchToolResponse{}
	require.NoError(t, proto.Unmarshal(pBytes, &res))

	assert.Equal(t, "smithy-test", res.GetToolName())
	assert.Equal(t, baseTime.Unix(), res.GetScanInfo().GetScanStartTime().GetSeconds())
	assert.Equal(t, "ab3d3290-cd9f-482c-97dc-ec48bdfcc4de", res.GetScanInfo().GetScanUuid())
	assert.Equal(t, 3, len(res.GetIssues()))

	for _, i := range []int{0, 1, 2} {
		require.Equal(t, fmt.Sprintf("target%d", i), res.GetIssues()[i].GetTarget())
		require.Equal(t, fmt.Sprintf("title%d", i), res.GetIssues()[i].GetTitle())
		require.Equal(t, fmt.Sprintf("desc%d", i), res.GetIssues()[i].GetDescription())
		require.Equal(t, fmt.Sprintf("cve%d", i), res.GetIssues()[i].GetCve())
	}
}

func TestParseMultiJSONMessages(t *testing.T) {
	testJSON := `{"Foo":"bar"}{"Foo":"barbar"}{"Foo":"barbarbar"}`

	inJSON, err := ParseMultiJSONMessages([]byte(testJSON))
	require.NoError(t, err)
	want := make([]testJ, len(inJSON))

	for i, v := range inJSON {
		var x testJ
		require.NoError(t, mapstructure.Decode(v, &x))
		want[i] = x
	}
	assert.Equal(t, want[0].Foo, "bar")
}

func TestGetPURLTarget(t *testing.T) {
	target := GetPURLTarget("deb", "debian", "curl", "7.68.0", nil, "")
	require.Equal(t, "pkg:deb/debian/curl@7.68.0", target)

	target = GetPURLTarget("bitbucket", "birkenfeld", "pygments-main", "244fd47e07d1014f0aed9c", nil, "")
	require.Equal(t, "pkg:bitbucket/birkenfeld/pygments-main@244fd47e07d1014f0aed9c", target)

	target = GetPURLTarget("docker", "customer", "dockerimage", "sha256:244fd47e07d1004f0aed9c", packageurl.Qualifiers{
		{Key: "repository_url", Value: "gcr.io"},
	}, "")
	require.Equal(t, "pkg:docker/customer/dockerimage@sha256:244fd47e07d1004f0aed9c?repository_url=gcr.io", target)

	target = GetPURLTarget("npm", "", "foobar", "12.3.1", nil, "")
	require.Equal(t, "pkg:npm/foobar@12.3.1", target)

	target = GetPURLTarget("pypi", "", "django", "1.11.1", nil, "")
	require.Equal(t, "pkg:pypi/django@1.11.1", target)

	target = GetPURLTarget("deb", "debian", "curl", "7.50.3-1", packageurl.Qualifiers{
		{Key: "arch", Value: "i386"},
		{Key: "distro", Value: "jessie"},
	}, "")

	require.Equal(t, "pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie", target)
}

func TestReadInFile(t *testing.T) {
	// Create a temporary file and write some data to it for the success case.
	successContent := []byte("Hello, world!")
	tmpfile, err := os.CreateTemp("", "example")
	require.NoError(t, err, "Unable to create temporary file")
	defer os.Remove(tmpfile.Name()) // clean up after

	_, err = tmpfile.Write(successContent)
	require.NoError(t, err, "Unable to write to temporary file")
	require.NoError(t, tmpfile.Close(), "Unable to close temporary file")

	tests := []struct {
		name    string
		file    string
		want    []byte
		wantErr bool
	}{
		{
			name:    "Success",
			file:    tmpfile.Name(),
			want:    successContent,
			wantErr: false,
		},
		{
			name:    "File does not exist",
			file:    "non_existent_file.txt",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			InResults = tt.file
			got, err := ReadInFile()
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadInFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			assert.Equal(t, tt.want, got, "ReadInFile() = %v, want %v", got, tt.want)
		})
	}
}

func TestGetFileTarget(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     string
	}{
		{
			name:     "Test with UNIX path",
			filePath: "/path/to/file.txt",
			want:     "file:///path/to/file.txt:1-2",
		},
		{
			name:     "Test with empty path",
			filePath: "",
			want:     "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, GetFileTarget(tc.filePath, 1, 2))
		})
	}
}

func TestEnsureValidFileTarget(t *testing.T) {
	tests := []struct {
		name       string
		fileTarget string
		want       string
		wantErr    bool
	}{
		{
			name:       "Valid File URI",
			fileTarget: "file:///path/to/file.txt:10-20",
			want:       "file:///path/to/file.txt:10-20",
			wantErr:    false,
		},
		{
			name:       "Valid URI, root path",
			fileTarget: "file:///file.txt:1-5",
			want:       "file:///file.txt:1-5",
			wantErr:    false,
		},
		{
			name:       "Invalid URI scheme",
			fileTarget: "http:///file.txt",
			want:       "",
			wantErr:    true,
		},
		{
			name:       "Empty URL",
			fileTarget: "",
			want:       "",
			wantErr:    true,
		},
		{
			name:       "Missing range end",
			fileTarget: "http:///file.txt:12",
			want:       "",
			wantErr:    true,
		},
		{
			name:       "Dir instead of file",
			fileTarget: "file:///path/to/dir:10-20",
			want:       "",
			wantErr:    true,
		},
		{
			name:       "Dir instead of file (trailing slash)",
			fileTarget: "file:///path/to/dir/:10-20",
			want:       "",
			wantErr:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := EnsureValidFileTarget(tc.fileTarget)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.want, got)
			}
		})
	}
}
