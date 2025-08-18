package paginator

import (
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

type ObjectPair struct {
	Finding       *vf.VulnerabilityFinding
	Vulnerability *ocsf.Vulnerability
	Index         int
}

func StreamObjects(findings []*vf.VulnerabilityFinding, pageSize int) <-chan []ObjectPair {
	ch := make(chan []ObjectPair)

	go func() {
		defer close(ch)
		batch := make([]ObjectPair, 0, pageSize)
		for _, finding := range findings {

			if finding == nil || finding.Finding == nil {
				continue // Skip nil Finding pointers
			}

			for objIdx, obj := range finding.Finding.GetVulnerabilities() {
				// Add this object to our current batch
				batch = append(batch, ObjectPair{
					Finding:       finding, // Pointer to the parent Finding
					Vulnerability: obj,     // Pointer to the actual Vulnerability
					Index:         objIdx,  // Where it was in the original slice
				})

				// Is our batch full?
				if len(batch) >= pageSize {
					// Send the full batch through the channel
					ch <- batch

					// Start a new batch (keep the capacity for efficiency)
					batch = make([]ObjectPair, 0, pageSize)
				}
			}
		}
		// Don't forget the last batch if it has items!
		if len(batch) > 0 {
			ch <- batch
		}
	}()

	return ch
}
