# Go Plist library

[![CI/CD](https://github.com/micromdm/plist/workflows/CI%2FCD/badge.svg)](https://github.com/micromdm/plist/actions) [![Go Reference](https://pkg.go.dev/badge/github.com/micromdm/plist.svg)](https://pkg.go.dev/github.com/micromdm/plist)

This Plist library is used for decoding and encoding Apple Property Lists in both XML and binary forms.

Example using HTTP streams:

```go
func someHTTPHandler(w http.ResponseWriter, r *http.Request) {
	var sparseBundleHeader struct {
		InfoDictionaryVersion *string `plist:"CFBundleInfoDictionaryVersion"`
		BandSize              *uint64 `plist:"band-size"`
		BackingStoreVersion   int     `plist:"bundle-backingstore-version"`
		DiskImageBundleType   string  `plist:"diskimage-bundle-type"`
		Size                  uint64  `plist:"unknownKey"`
	}

    // decode an HTTP request body into the sparseBundleHeader struct
	if err := plist.NewXMLDecoder(r.Body).Decode(&sparseBundleHeader); err != nil {
		log.Println(err)
        return
	}
}
```

## Credit

This library is based on the [DHowett go-plist](https://github.com/DHowett/go-plist) library but has an API that is more like the XML and JSON package in the Go standard library. I.e. the `plist.Decoder()` accepts an `io.Reader` instead of an `io.ReadSeeker` 
