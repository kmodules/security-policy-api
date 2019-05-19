package v1beta1

import (
	"fmt"
	"github.com/golang/glog"
	jsoniter "github.com/json-iterator/go"
	policy "k8s.io/api/policy/v1beta1"
	kerr "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	kutil "kmodules.xyz/client-go"
	pu "kmodules.xyz/client-go/policy/v1beta1"
	scc "kmodules.xyz/openshift/apis/security/v1"
	occ "kmodules.xyz/openshift/client/clientset/versioned"
	su "kmodules.xyz/openshift/client/clientset/versioned/typed/security/v1/util"
	api "kmodules.xyz/security-policy-api/apis/policy/v1beta1"
)

func init() {
	err := scc.Install(scheme.Scheme)
	if err != nil {
		panic(err)
	}
}

var json = jsoniter.ConfigFastest

type SecurityPolicyTransformerFunc func(*api.SecurityPolicy) *api.SecurityPolicy

// SecurityPoliciesGetter has a method to return a SecurityPolicyInterface.
// A group's client should implement this interface.
type SecurityPoliciesGetter interface {
	SecurityPolicies() SecurityPolicyInterface
}

// SecurityPolicyInterface has methods to work with SecurityPolicy resources.
type SecurityPolicyInterface interface {
	Create(*api.SecurityPolicy) (*api.SecurityPolicy, error)
	Delete(obj runtime.Object, options *metav1.DeleteOptions) error
	Get(obj runtime.Object, options metav1.GetOptions) (*api.SecurityPolicy, error)
	List(opts metav1.ListOptions) (*api.SecurityPolicyList, error)
	Patch(cur *api.SecurityPolicy, transform SecurityPolicyTransformerFunc) (*api.SecurityPolicy, kutil.VerbType, error)
	PatchObject(cur, mod *api.SecurityPolicy) (*api.SecurityPolicy, kutil.VerbType, error)
	CreateOrPatch(obj runtime.Object, transform SecurityPolicyTransformerFunc) (*api.SecurityPolicy, kutil.VerbType, error)
}

// securitypolicies implements SecurityPolicyInterface
type securitypolicies struct {
	kc kubernetes.Interface
	oc occ.Interface
}

var _ SecurityPolicyInterface = &securitypolicies{}

// newSecurityPolicies returns a SecurityPolicies
func newSecurityPolicies(kc kubernetes.Interface, oc occ.Interface) *securitypolicies {
	return &securitypolicies{
		kc: kc,
		oc: oc,
	}
}

func (c *securitypolicies) Create(w *api.SecurityPolicy) (*api.SecurityPolicy, error) {
	out, err := c.kc.PolicyV1beta1().PodSecurityPolicies().Create(ToPodSecurityPolicy(w))
	if err != nil {
		return nil, err
	}
	if c.oc != nil {
		_, err = c.oc.SecurityV1().SecurityContextConstraints().Create(ToSecurityContextConstraints(w))
		if err != nil {
			return nil, err
		}
	}
	return FromPodSecurityPolicy(out), nil
}

func (c *securitypolicies) Delete(obj runtime.Object, options *metav1.DeleteOptions) error {
	switch t := obj.(type) {
	case *api.SecurityPolicy:
		err := c.kc.PolicyV1beta1().PodSecurityPolicies().Delete(t.ObjectMeta.Name, options)
		if err != nil {
			return err
		}
		if c.oc != nil {
			return c.oc.SecurityV1().SecurityContextConstraints().Delete(t.ObjectMeta.Name, options)
		}
		return nil
	case *policy.PodSecurityPolicy:
		return c.kc.PolicyV1beta1().PodSecurityPolicies().Delete(t.ObjectMeta.Name, options)
	case *scc.SecurityContextConstraints:
		return c.oc.SecurityV1().SecurityContextConstraints().Delete(t.ObjectMeta.Name, options)
	default:
		return fmt.Errorf("the object is not a security policy")
	}
}

func (c *securitypolicies) Get(obj runtime.Object, options metav1.GetOptions) (*api.SecurityPolicy, error) {
	var out runtime.Object
	var err error
	switch t := obj.(type) {
	case *api.SecurityPolicy:
		out, err = c.kc.PolicyV1beta1().PodSecurityPolicies().Get(t.ObjectMeta.Name, options)
	case *policy.PodSecurityPolicy:
		out, err = c.kc.PolicyV1beta1().PodSecurityPolicies().Get(t.ObjectMeta.Name, options)
	case *scc.SecurityContextConstraints:
		out, err = c.oc.SecurityV1().SecurityContextConstraints().Get(t.ObjectMeta.Name, options)
	default:
		err = fmt.Errorf("the object is not a pod or does not have a pod template")
	}
	if err != nil {
		return nil, err
	}
	return ConvertToSecurityPolicy(out)
}

func (c *securitypolicies) List(opts metav1.ListOptions) (*api.SecurityPolicyList, error) {
	options := metav1.ListOptions{
		LabelSelector:   opts.LabelSelector,
		FieldSelector:   opts.FieldSelector,
		ResourceVersion: opts.ResourceVersion,
		TimeoutSeconds:  opts.TimeoutSeconds,
	}
	list := api.SecurityPolicyList{Items: make([]api.SecurityPolicy, 0)}

	if c.kc != nil {
		{
			objects, err := c.kc.PolicyV1beta1().PodSecurityPolicies().List(options)
			if err != nil {
				return nil, err
			}
			err = meta.EachListItem(objects, func(obj runtime.Object) error {
				w, err := ConvertToSecurityPolicy(obj)
				if err != nil {
					return err
				}
				list.Items = append(list.Items, *w)
				return nil
			})
			if err != nil {
				return nil, err
			}
		}
	}
	if c.oc != nil {
		objects, err := c.oc.SecurityV1().SecurityContextConstraints().List(options)
		if err != nil {
			return nil, err
		}
		err = meta.EachListItem(objects, func(obj runtime.Object) error {
			w, err := ConvertToSecurityPolicy(obj)
			if err != nil {
				return err
			}
			list.Items = append(list.Items, *w)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	return &list, nil
}

func (c *securitypolicies) Patch(cur *api.SecurityPolicy, transform SecurityPolicyTransformerFunc) (*api.SecurityPolicy, kutil.VerbType, error) {
	return c.PatchObject(cur, transform(cur.DeepCopy()))
}

func (c *securitypolicies) PatchObject(cur, mod *api.SecurityPolicy) (*api.SecurityPolicy, kutil.VerbType, error) {
	if c.oc != nil {
		_, _, err := su.PatchSecurityContextConstraintsObject(c.oc, ToSecurityContextConstraints(cur), ToSecurityContextConstraints(mod))
		if err != nil {
			return nil, kutil.VerbUnchanged, err
		}
	}

	out, kt, err := pu.PatchPodSecurityPolicyObject(c.kc, ToPodSecurityPolicy(cur), ToPodSecurityPolicy(mod))
	if err != nil {
		return nil, kutil.VerbUnchanged, err
	}
	return FromPodSecurityPolicy(out), kt, nil
}

func (c *securitypolicies) CreateOrPatch(obj runtime.Object, transform SecurityPolicyTransformerFunc) (*api.SecurityPolicy, kutil.VerbType, error) {
	gvk := obj.GetObjectKind().GroupVersionKind()
	if gvk.String() == "" {
		return nil, kutil.VerbUnchanged, fmt.Errorf("obj missing GroupVersionKind")
	}

	cur, err := c.Get(obj, metav1.GetOptions{})
	if kerr.IsNotFound(err) {
		name, err := meta.NewAccessor().Name(obj)
		if err != nil {
			return nil, kutil.VerbUnchanged, err
		}
		glog.V(3).Infof("Creating %s %s.", gvk, name)
		out, err := c.Create(transform(&api.SecurityPolicy{
			TypeMeta: metav1.TypeMeta{
				Kind:       gvk.Kind,
				APIVersion: gvk.GroupVersion().String(),
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
		}))
		return out, kutil.VerbCreated, err
	} else if err != nil {
		return nil, kutil.VerbUnchanged, err
	}
	return c.Patch(cur, transform)
}
