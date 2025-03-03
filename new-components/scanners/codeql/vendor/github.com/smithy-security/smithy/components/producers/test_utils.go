package producers

import (
	"os"
	"os/exec"
	"reflect"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	smithyv1 "github.com/smithy-security/smithy/api/proto/v1"
)

// TestEndToEnd is a helper function to test the end-to-end functionality of a producer.
func TestEndToEnd(t *testing.T, inPath string, expectedPbPath string) error {
	tempResultFile, err := os.CreateTemp("", "smithy-test-*.pb")
	if err != nil {
		return err
	}

	// Create the command
	cmd := exec.Command("go", "run", "./main.go", "-in", inPath, "-out", tempResultFile.Name())
	err = cmd.Run()
	if err != nil {
		return err
	}

	// Read the scanContent from the temporary file
	actualResponse, err := readResponseFromFile(tempResultFile.Name())
	if err != nil {
		return err
	}

	// Read the content from the expected output file in the repository
	expectedResponse, err := readResponseFromFile(expectedPbPath)
	if err != nil {
		return err
	}

	// Assert that the actual response is equal to the expected response
	if len(expectedResponse.Issues) != len(actualResponse.Issues) {
		t.Errorf("Length of expectedResponse.Issues (%d) and actualResponse.Issues (%d) are not equal", len(expectedResponse.Issues), len(actualResponse.Issues))
	} else {
		for i, v := range expectedResponse.Issues {
			if !reflect.DeepEqual(v, actualResponse.Issues[i]) {
				t.Errorf("expectedResponse.Issues[%d] and actualResponse.Issues[%d] are not equal: %v != %v", i, i, v, actualResponse.Issues[i])
			}
		}
	}

	// clean up
	err = os.Remove(tempResultFile.Name())
	return err
}

func readResponseFromFile(filePath string) (*smithyv1.LaunchToolResponse, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var response smithyv1.LaunchToolResponse
	err = proto.Unmarshal(content, &response)
	if err != nil {
		return nil, err
	}
	response.ScanInfo.ScanStartTime = &timestamppb.Timestamp{}

	return &response, nil
}
