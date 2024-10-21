package manifests

import (
	"context"
	"fmt"

	tektonv1beta1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	batchv1 "k8s.io/api/batch/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	jsonserializer "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/client-go/kubernetes/scheme"

	"github.com/smithy-security/smithy/pkg/files"
)

var K8sObjDecoder runtime.Decoder
var CodecFactory serializer.CodecFactory
var TektonV1Beta1ObjEncoder runtime.Encoder
var BatchV1ObjEncoder runtime.Encoder

func init() {
	sch := runtime.NewScheme()
	if err := scheme.AddToScheme(sch); err != nil {
		panic(err)
	}
	if err := tektonv1beta1.AddToScheme(sch); err != nil {
		panic(err)
	}
	CodecFactory = serializer.NewCodecFactory(sch)
	K8sObjDecoder = CodecFactory.UniversalDeserializer()
	yamlSerializer := jsonserializer.NewYAMLSerializer(jsonserializer.DefaultMetaFactory, scheme.Scheme, scheme.Scheme)
	TektonV1Beta1ObjEncoder = CodecFactory.EncoderForVersion(yamlSerializer, tektonv1beta1.SchemeGroupVersion)
	BatchV1ObjEncoder = CodecFactory.EncoderForVersion(yamlSerializer, batchv1.SchemeGroupVersion)
}

// LoadK8sManifest resolves the path or the URI, fetches the bytes stored in it and then attempts
// to deserializer the bytes into a known K8s object struct.
func LoadK8sManifest(ctx context.Context, configurationDir, pathOrURI, targetFile string) (runtime.Object, *schema.GroupVersionKind, error) {
	loader, err := files.NewLoader(configurationDir, pathOrURI, targetFile)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: could not resolve path or URI: %w", pathOrURI, err)
	}

	manifestBytes, err := loader.Load(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: could not load path or URI: %w", loader.Path(), err)
	}

	obj, gKV, err := K8sObjDecoder.Decode(manifestBytes, nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: could not decode file into a K8s object:3 %w", loader.Path(), err)
	}

	return obj, gKV, nil
}
