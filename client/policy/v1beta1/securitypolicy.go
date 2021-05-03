/*
Copyright The Kmodules Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1beta1

import (
	"context"
	"fmt"

	kutil "kmodules.xyz/client-go"
	pu "kmodules.xyz/client-go/policy/v1beta1"
	scc "kmodules.xyz/openshift/apis/security/v1"
	occ "kmodules.xyz/openshift/client/clientset/versioned"
	su "kmodules.xyz/openshift/client/clientset/versioned/typed/security/v1/util"
	api "kmodules.xyz/security-policy-api/apis/policy/v1beta1"

	"github.com/golang/glog"
	policy "k8s.io/api/policy/v1beta1"
	kerr "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
)

func init() {
	err := scc.Install(scheme.Scheme)
	if err != nil {
		panic(err)
	}
}

type SecurityPolicyTransformerFunc func(*api.SecurityPolicy) *api.SecurityPolicy

// SecurityPoliciesGetter has a method to return a SecurityPolicyInterface.
// A group's client should implement this interface.
type SecurityPoliciesGetter interface {
	SecurityPolicies() SecurityPolicyInterface
}

// SecurityPolicyInterface has methods to work with SecurityPolicy resources.
type SecurityPolicyInterface interface {
	Create(ctx context.Context, obj *api.SecurityPolicy, opts metav1.CreateOptions) (*api.SecurityPolicy, error)
	Delete(ctx context.Context, obj runtime.Object, opts metav1.DeleteOptions) error
	Get(ctx context.Context, obj runtime.Object, opts metav1.GetOptions) (*api.SecurityPolicy, error)
	List(ctx context.Context, opts metav1.ListOptions) (*api.SecurityPolicyList, error)
	Patch(ctx context.Context, cur *api.SecurityPolicy, transform SecurityPolicyTransformerFunc, opts metav1.PatchOptions) (*api.SecurityPolicy, kutil.VerbType, error)
	PatchObject(ctx context.Context, cur, mod *api.SecurityPolicy, opts metav1.PatchOptions) (*api.SecurityPolicy, kutil.VerbType, error)
	CreateOrPatch(ctx context.Context, obj runtime.Object, transform SecurityPolicyTransformerFunc, opts metav1.PatchOptions) (*api.SecurityPolicy, kutil.VerbType, error)
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

func (c *securitypolicies) Create(ctx context.Context, obj *api.SecurityPolicy, opts metav1.CreateOptions) (*api.SecurityPolicy, error) {
	out, err := c.kc.PolicyV1beta1().PodSecurityPolicies().Create(ctx, ToPodSecurityPolicy(obj), opts)
	if err != nil {
		return nil, err
	}
	if c.oc != nil {
		_, err = c.oc.SecurityV1().SecurityContextConstraints().Create(ctx, ToSecurityContextConstraints(obj), opts)
		if err != nil {
			return nil, err
		}
	}
	return FromPodSecurityPolicy(out), nil
}

func (c *securitypolicies) Delete(ctx context.Context, obj runtime.Object, opts metav1.DeleteOptions) error {
	switch t := obj.(type) {
	case *api.SecurityPolicy:
		err := c.kc.PolicyV1beta1().PodSecurityPolicies().Delete(ctx, t.ObjectMeta.Name, opts)
		if err != nil {
			return err
		}
		if c.oc != nil {
			return c.oc.SecurityV1().SecurityContextConstraints().Delete(ctx, t.ObjectMeta.Name, opts)
		}
		return nil
	case *policy.PodSecurityPolicy:
		return c.kc.PolicyV1beta1().PodSecurityPolicies().Delete(ctx, t.ObjectMeta.Name, opts)
	case *scc.SecurityContextConstraints:
		return c.oc.SecurityV1().SecurityContextConstraints().Delete(ctx, t.ObjectMeta.Name, opts)
	default:
		return fmt.Errorf("the object is not a security policy")
	}
}

func (c *securitypolicies) Get(ctx context.Context, obj runtime.Object, opts metav1.GetOptions) (*api.SecurityPolicy, error) {
	var out runtime.Object
	var err error
	switch t := obj.(type) {
	case *api.SecurityPolicy:
		out, err = c.kc.PolicyV1beta1().PodSecurityPolicies().Get(ctx, t.ObjectMeta.Name, opts)
	case *policy.PodSecurityPolicy:
		out, err = c.kc.PolicyV1beta1().PodSecurityPolicies().Get(ctx, t.ObjectMeta.Name, opts)
	case *scc.SecurityContextConstraints:
		out, err = c.oc.SecurityV1().SecurityContextConstraints().Get(ctx, t.ObjectMeta.Name, opts)
	default:
		err = fmt.Errorf("the object is not a pod or does not have a pod template")
	}
	if err != nil {
		return nil, err
	}
	return ConvertToSecurityPolicy(out)
}

func (c *securitypolicies) List(ctx context.Context, opts metav1.ListOptions) (*api.SecurityPolicyList, error) {
	options := metav1.ListOptions{
		LabelSelector:   opts.LabelSelector,
		FieldSelector:   opts.FieldSelector,
		ResourceVersion: opts.ResourceVersion,
		TimeoutSeconds:  opts.TimeoutSeconds,
	}
	list := api.SecurityPolicyList{Items: make([]api.SecurityPolicy, 0)}

	if c.kc != nil {
		{
			objects, err := c.kc.PolicyV1beta1().PodSecurityPolicies().List(ctx, options)
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
		objects, err := c.oc.SecurityV1().SecurityContextConstraints().List(ctx, options)
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

func (c *securitypolicies) Patch(ctx context.Context, cur *api.SecurityPolicy, transform SecurityPolicyTransformerFunc, opts metav1.PatchOptions) (*api.SecurityPolicy, kutil.VerbType, error) {
	return c.PatchObject(ctx, cur, transform(cur.DeepCopy()), opts)
}

func (c *securitypolicies) PatchObject(ctx context.Context, cur, mod *api.SecurityPolicy, opts metav1.PatchOptions) (*api.SecurityPolicy, kutil.VerbType, error) {
	if c.oc != nil {
		_, _, err := su.PatchSecurityContextConstraintsObject(ctx, c.oc, ToSecurityContextConstraints(cur), ToSecurityContextConstraints(mod), opts)
		if err != nil {
			return nil, kutil.VerbUnchanged, err
		}
	}

	out, kt, err := pu.PatchPodSecurityPolicyObject(ctx, c.kc, ToPodSecurityPolicy(cur), ToPodSecurityPolicy(mod), opts)
	if err != nil {
		return nil, kutil.VerbUnchanged, err
	}
	return FromPodSecurityPolicy(out), kt, nil
}

func (c *securitypolicies) CreateOrPatch(ctx context.Context, obj runtime.Object, transform SecurityPolicyTransformerFunc, opts metav1.PatchOptions) (*api.SecurityPolicy, kutil.VerbType, error) {
	gvk := obj.GetObjectKind().GroupVersionKind()
	if gvk.String() == "" {
		return nil, kutil.VerbUnchanged, fmt.Errorf("obj missing GroupVersionKind")
	}

	cur, err := c.Get(ctx, obj, metav1.GetOptions{})
	if kerr.IsNotFound(err) {
		name, err := meta.NewAccessor().Name(obj)
		if err != nil {
			return nil, kutil.VerbUnchanged, err
		}
		glog.V(3).Infof("Creating %s %s.", gvk, name)
		out, err := c.Create(ctx, transform(&api.SecurityPolicy{
			TypeMeta: metav1.TypeMeta{
				Kind:       gvk.Kind,
				APIVersion: gvk.GroupVersion().String(),
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
		}), metav1.CreateOptions{})
		return out, kutil.VerbCreated, err
	} else if err != nil {
		return nil, kutil.VerbUnchanged, err
	}
	return c.Patch(ctx, cur, transform, opts)
}
