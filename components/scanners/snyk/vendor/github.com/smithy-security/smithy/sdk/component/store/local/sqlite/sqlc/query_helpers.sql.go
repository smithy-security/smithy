package sqlc

// FindingRow is an interface to simplify processing of results returned by the
// queries
type FindingRow interface {
	GetID() int64
	GetDetails() string
}

func (f FindingsPageByIDRow) GetID() int64 {
	return f.ID
}

func (f FindingsPageByIDRow) GetDetails() string {
	return f.Details
}

func (f FindingsByIDRow) GetID() int64 {
	return f.ID
}

func (f FindingsByIDRow) GetDetails() string {
	return f.Details
}
