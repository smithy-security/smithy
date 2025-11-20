package parser

import (
	"fmt"
)

type RunInfo struct {
	Type             string
	Level            int
	FromOffset       int64
	ToOffset         int64
	Length           int64
	CompressedLength int64
	IsSparse         bool
	ClusterSize      int64
	Reader           string
}

func (self RunInfo) String() string {
	prefix := ""
	for i := 0; i < self.Level; i++ {
		prefix += " "
	}

	properties := ""
	if self.IsSparse {
		properties += "Sparse "
	}
	if self.CompressedLength != 0 {
		properties += fmt.Sprintf("Compressed Length %v", self.CompressedLength)
	}

	return fmt.Sprintf("%s %d %v: FileOffset %v -> DiskOffset %v (Length %v, %v Cluster %v) Delegate %v",
		prefix, self.Level,
		self.Type, self.FromOffset, self.ToOffset, self.Length,
		properties, self.ClusterSize, self.Reader)
}

func DebugRawRuns(runs []*Run) {
	fmt.Printf("Runs ....\n")

	for idx, r := range runs {
		fmt.Printf("%d Disk Offset %d  RelativeUrnOffset %d (Length %d)\n",
			idx, r.Offset, r.RelativeUrnOffset, r.Length)
	}
}

func DebugRuns(stream RangeReaderAt, level int) []*RunInfo {
	result := make([]*RunInfo, 0)

	switch t := stream.(type) {
	case *MappedReader:
		result = append(result, &RunInfo{
			Type:             "MappedReader",
			Level:            level,
			FromOffset:       t.FileOffset,
			ToOffset:         t.TargetOffset,
			Length:           t.Length,
			CompressedLength: t.CompressedLength,
			IsSparse:         t.IsSparse,
			ClusterSize:      t.ClusterSize,
			Reader:           fmt.Sprintf("%T", t.Reader),
		})

		reader_t, ok := t.Reader.(RangeReaderAt)
		if ok {
			result = append(result, DebugRuns(reader_t, level+1)...)
		}

	case *RangeReader:
		for _, r := range t.runs {
			result = append(result, DebugRuns(r, level)...)
		}
	}

	return result
}
