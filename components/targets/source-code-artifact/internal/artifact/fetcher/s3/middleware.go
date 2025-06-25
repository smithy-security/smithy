package s3

import (
	"context"
	"fmt"

	v4signer "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/go-errors/errors"
)

const acceptEncodingHeader = "Accept-Encoding"

type acceptEncodingKey struct{}

func signForGCP(opts *s3.Options) {
	opts.APIOptions = append(
		opts.APIOptions,
		func(stack *middleware.Stack) error {
			if err := stack.Finalize.Insert(dropAcceptEncodingHeader, "Signing", middleware.Before); err != nil {
				return err
			}

			if err := stack.Finalize.Insert(replaceAcceptEncodingHeader, "Signing", middleware.After); err != nil {
				return err
			}

			return nil
		},
	)
}

func getAcceptEncodingKey(ctx context.Context) string {
	v, _ := middleware.GetStackValue(ctx, acceptEncodingKey{}).(string)
	return v
}

func setAcceptEncodingKey(ctx context.Context, value string) context.Context {
	return middleware.WithStackValue(ctx, acceptEncodingKey{}, value)
}

var dropAcceptEncodingHeader = middleware.FinalizeMiddlewareFunc(
	"DropAcceptEncodingHeader",
	func(
		ctx context.Context,
		in middleware.FinalizeInput,
		next middleware.FinalizeHandler,
	) (out middleware.FinalizeOutput, metadata middleware.Metadata, err error) {
		req, ok := in.Request.(*smithyhttp.Request)
		if !ok {
			return out, metadata, &v4signer.SigningError{Err: errors.Errorf("unexpected request middleware type %T", in.Request)}
		}

		ae := req.Header.Get(acceptEncodingHeader)
		ctx = setAcceptEncodingKey(ctx, ae)
		req.Header.Del(acceptEncodingHeader)
		in.Request = req

		return next.HandleFinalize(ctx, in)
	},
)

var replaceAcceptEncodingHeader = middleware.FinalizeMiddlewareFunc(
	"ReplaceAcceptEncodingHeader",
	func(
		ctx context.Context,
		in middleware.FinalizeInput,
		next middleware.FinalizeHandler,
	) (out middleware.FinalizeOutput, metadata middleware.Metadata, err error) {
		req, ok := in.Request.(*smithyhttp.Request)
		if !ok {
			return out, metadata, &v4signer.SigningError{Err: fmt.Errorf("unexpected request middleware type %T", in.Request)}
		}

		ae := getAcceptEncodingKey(ctx)
		req.Header.Set(acceptEncodingHeader, ae)
		in.Request = req

		return next.HandleFinalize(ctx, in)
	},
)
