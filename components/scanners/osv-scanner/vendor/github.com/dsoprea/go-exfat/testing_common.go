package exfat

import (
	"path"
)

var (
	assetPath = ""
)

func init() {
	assetPath = path.Join("test", "assets")
}
