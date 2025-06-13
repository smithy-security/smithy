package component

import (
	"bytes"
	"context"
	"os"
	"path"
	"strings"

	"github.com/go-errors/errors"
	"google.golang.org/protobuf/encoding/protojson"

	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	sdklogger "github.com/smithy-security/smithy/sdk/logger"
)

const SCANNER_TARGET_METADATA_PATH_ENV_VAR = "TARGET_METADATA_PATH"

type scanner_ctx_key int

const (
	SCANNER_TARGET_METADATA_CTX_KEY scanner_ctx_key = iota
)

// RunScanner runs a scanner after initialising the run context.
func RunScanner(ctx context.Context, scanner Scanner, opts ...RunnerOption) error {
	return run(
		ctx,
		func(ctx context.Context, cfg *RunnerConfig) error {
			var (
				instanceID = cfg.InstanceID
				logger     = sdklogger.LoggerFromContext(ctx).With(sdklogger.LogKeyComponentType, "scanner")
				store      = cfg.StoreConfig.Storer
			)

			defer func() {
				if err := store.Close(ctx); err != nil {
					logger.With(sdklogger.LogKeyError, err.Error()).Error("closing step failed, ignoring...")
				}
			}()

			logger.Debug("preparing to execute component...")
			logger.Debug("checking if there are target metadata to add to findings")
			metadataPath, exists := os.LookupEnv(SCANNER_TARGET_METADATA_PATH_ENV_VAR)
			if exists {
				logger.Debug("checking if there are target metadata to add to context")
				if !strings.HasSuffix(metadataPath, "target.json") {
					metadataPath = path.Join(metadataPath, "target.json")
				}

				fstat, err := os.Stat(metadataPath)
				if err != nil {
					return errors.Errorf("%s: could not open target metadata file: %w", metadataPath, err)
				} else if fstat.IsDir() || !fstat.Mode().IsRegular() {
					return errors.Errorf("%s: metadata file is either a directory or not a regular file", metadataPath)
				}

				fd, err := os.OpenFile(metadataPath, os.O_RDONLY, 0666)
				if err != nil {
					return errors.Errorf("%s: could not read metadata file: %w", metadataPath, err)
				}

				buffer := bytes.NewBuffer([]byte{})
				_, err = buffer.ReadFrom(fd)
				if err != nil {
					return errors.Errorf("%s: could read bytes from target metadata file: %w", metadataPath, err)
				}

				targetMetadata := ocsffindinginfo.DataSource{}
				err = protojson.Unmarshal(buffer.Bytes(), &targetMetadata)
				if err != nil {
					return errors.Errorf("%s: could not unmarshal target metadata: %w", metadataPath, err)
				}

				ctx = context.WithValue(ctx, SCANNER_TARGET_METADATA_CTX_KEY, &targetMetadata)
				logger.Debug("injected target metadata into component's context")
			}
			logger.Debug("preparing to execute transform step...")

			rawFindings, err := scanner.Transform(ctx)
			switch {
			case err != nil:
				logger.
					With(sdklogger.LogKeyError, err.Error()).
					Debug("could not execute transform step")
				return errors.Errorf("could not transform raw findings: %w", err)
			case len(rawFindings) == 0:
				logger.Debug("no raw findings found, skipping persisting step...")
				return nil
			}

			logger = logger.
				With(sdklogger.LogKeyNumRawFindings, len(rawFindings))
			logger.Debug("transform step completed!")
			logger.Debug("preparing to execute validate step...")

			for _, rv := range rawFindings {
				if err := store.Validate(rv); err != nil {
					logger.
						With(sdklogger.LogKeyError, err.Error()).
						With(sdklogger.LogKeyRawFinding, rv).
						Error("invalid raw finding")
					return errors.Errorf("invalid raw finding: %w", err)
				}
			}

			logger.Debug("validate step completed!")
			logger.Debug("preparing to execute store step...")

			if err := store.Write(ctx, instanceID, rawFindings); err != nil {
				logger.
					With(sdklogger.LogKeyError, err.Error()).
					Debug("could not execute store step")
				return errors.Errorf("could not store vulnerabilities: %w", err)
			}

			logger.Debug("store step completed!")
			logger.Debug("component has completed successfully!")

			return nil
		},
		opts...,
	)
}

// TargetMetadataFromCtx is a small utility to return the target metadata
// picked up from the targets injected into the transformer ctx
func TargetMetadataFromCtx(ctx context.Context) *ocsffindinginfo.DataSource {
	targetMetadataVal := ctx.Value(SCANNER_TARGET_METADATA_CTX_KEY)
	targetMetadata, ok := targetMetadataVal.(*ocsffindinginfo.DataSource)
	if !ok {
		return &ocsffindinginfo.DataSource{}
	}

	return targetMetadata
}
