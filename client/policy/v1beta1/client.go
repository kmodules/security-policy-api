package v1beta1

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"kmodules.xyz/client-go/discovery"
	scc "kmodules.xyz/openshift/apis/security/v1"
	occ "kmodules.xyz/openshift/client/clientset/versioned"
	wpi "kmodules.xyz/security-policy-api/apis/policy/v1beta1"
)

type Interface interface {
	SecurityPoliciesGetter
}

// Client is used to interact with features provided by the storage.k8s.io group.
type Client struct {
	kc kubernetes.Interface
	oc occ.Interface
}

func (c *Client) SecurityPolicies() SecurityPolicyInterface {
	return newSecurityPolicies(c.kc, c.oc)
}

// NewForConfig creates a new Client for the given config.
func NewForConfig(c *rest.Config) (*Client, error) {
	kc, err := kubernetes.NewForConfig(c)
	if err != nil {
		return nil, err
	}
	var oc occ.Interface
	if discovery.IsPreferredAPIResource(kc.Discovery(), scc.GroupVersion.String(), wpi.KindSecurityContextConstraints) {
		oc, err = occ.NewForConfig(c)
		if err != nil {
			return nil, err
		}
	}
	return &Client{kc, oc}, nil
}

// NewForConfigOrDie creates a new Client for the given config and
// panics if there is an error in the config.
func NewForConfigOrDie(c *rest.Config) *Client {
	kc := kubernetes.NewForConfigOrDie(c)
	var oc occ.Interface
	var err error
	if discovery.IsPreferredAPIResource(kc.Discovery(), scc.GroupVersion.String(), wpi.KindSecurityContextConstraints) {
		oc, err = occ.NewForConfig(c)
		if err != nil {
			panic(err)
		}
	}
	return &Client{kc, oc}
}

// New creates a new Client for the given RESTClient.
func New(kc kubernetes.Interface, oc occ.Interface) *Client {
	return &Client{kc, oc}
}
