package sarif

// Tool ...
type Tool struct {
	Driver     *ToolComponent   `json:"driver"`
	Extensions []*ToolComponent `json:"extensions,omitempty"`
	PropertyBag
}

// NewTool creates a new Tool and returns a pointer to it
func NewTool(driver *ToolComponent) *Tool {
	return &Tool{
		Driver: driver,
	}
}

// NewSimpleTool creates a new SimpleTool and returns a pointer to it
func NewSimpleTool(driverName string) *Tool {
	return &Tool{
		Driver: NewDriver(driverName),
	}
}

// WithExtensions sets the Extensions
func (tool *Tool) WithExtensions(extensions []*ToolComponent) *Tool {
	tool.Extensions = extensions
	return tool
}

// AddExtension ...
func (tool *Tool) AddExtension(extension *ToolComponent) {
	tool.Extensions = append(tool.Extensions, extension)
}
