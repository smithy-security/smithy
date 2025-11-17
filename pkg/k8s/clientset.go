package k8s

import (
	"context"

	"github.com/go-errors/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	k8sclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
)

// ClientInterface is an interface implemented by our K8s Go clients
type ClientInterface interface {
	k8sclient.Interface
	// Apply replicates the behaviour of the `kubectl apply` command
	Apply(ctx context.Context, obj runtime.Object, namespace string, forceConflicts bool) error
	// RESTMapper returns an instance implementing the `meta.RESTMapper` interface
	RESTMapper() meta.RESTMapper
}

type clientSet struct {
	*k8sclient.Clientset
	fieldManager  string
	dynamicClient dynamic.Interface
	restMapper    meta.RESTMapper
}

// NewTypedClientForConfig returns an implementation of the `ClientInterface`
// using the provided configuration.
func NewTypedClientForConfig(config *rest.Config, fieldManager string) (ClientInterface, error) {
	k8sClientSet, err := k8sclient.NewForConfig(config)
	if err != nil {
		return nil, errors.Errorf("could not initialise K8s clienset: %w", err)
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	deferredRESTMapper := restmapper.NewDeferredDiscoveryRESTMapper(
		memory.NewMemCacheClient(
			k8sClientSet.Discovery(),
		),
	)

	return clientSet{
		Clientset:     k8sClientSet,
		fieldManager:  fieldManager,
		dynamicClient: dynamicClient,
		restMapper:    deferredRESTMapper,
	}, nil
}

// Apply replicates the behaviour of the `kubectl apply` command replacing the
// object in the cluster if it exists with the current version or
func (c clientSet) Apply(ctx context.Context, obj runtime.Object, namespace string, forceConflicts bool) error {
	gvr, err := c.restMapper.RESTMapping(
		obj.GetObjectKind().GroupVersionKind().GroupKind(),
		obj.GetObjectKind().GroupVersionKind().Version,
	)
	if err != nil {
		return errors.Errorf("could not resolve resource APi of obj: %w", err)
	}

	metadataAccessor := meta.NewAccessor()
	name, err := metadataAccessor.Name(obj)
	if err != nil {
		return errors.Errorf("could not get the name of the K8s object: %w", err)
	}

	objData, err := runtime.Encode(unstructured.UnstructuredJSONScheme, obj)
	if err != nil {
		return errors.Errorf("%s/%s: could not convert runtime object into unstructured data: %w", namespace, name, err)
	}

	_, err = c.dynamicClient.
		Resource(gvr.Resource).
		Namespace(namespace).
		Patch(
			ctx,
			name,
			k8stypes.ApplyPatchType,
			objData,
			metav1.PatchOptions{
				FieldManager: c.fieldManager,
				Force:        &forceConflicts,
			},
		)

	if err != nil {
		return errors.Errorf("%s/%s: there was an issue while attempting to apply resource: %w", namespace, name, err)
	}
	return nil
}

// RESTMapper returns an instance of properly configured RESTMapper
func (c clientSet) RESTMapper() meta.RESTMapper {
	return c.restMapper
}
