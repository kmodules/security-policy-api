/*
Copyright AppsCode Inc. and Contributors

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

package util

import (
	"context"

	kutil "kmodules.xyz/client-go"
	api "kmodules.xyz/openshift/apis/security/v1"
	cs "kmodules.xyz/openshift/client/clientset/versioned"

	"github.com/golang/glog"
	"github.com/pkg/errors"
	kerr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/apimachinery/pkg/util/wait"
)

func CreateOrPatchSecurityContextConstraints(
	ctx context.Context,
	c cs.Interface,
	meta metav1.ObjectMeta,
	transform func(*api.SecurityContextConstraints) *api.SecurityContextConstraints,
	opts metav1.PatchOptions,
) (*api.SecurityContextConstraints, kutil.VerbType, error) {
	cur, err := c.SecurityV1().SecurityContextConstraints().Get(ctx, meta.Name, metav1.GetOptions{})
	if kerr.IsNotFound(err) {
		glog.V(3).Infof("Creating SecurityContextConstraints %s/%s.", meta.Namespace, meta.Name)
		out, err := c.SecurityV1().SecurityContextConstraints().Create(ctx, transform(&api.SecurityContextConstraints{
			TypeMeta: metav1.TypeMeta{
				Kind:       "SecurityContextConstraints",
				APIVersion: api.SchemeGroupVersion.String(),
			},
			ObjectMeta: meta,
		}), metav1.CreateOptions{
			DryRun:       opts.DryRun,
			FieldManager: opts.FieldManager,
		})
		return out, kutil.VerbCreated, err
	} else if err != nil {
		return nil, kutil.VerbUnchanged, err
	}
	return PatchSecurityContextConstraints(ctx, c, cur, transform, opts)
}

func PatchSecurityContextConstraints(
	ctx context.Context,
	c cs.Interface,
	cur *api.SecurityContextConstraints,
	transform func(*api.SecurityContextConstraints) *api.SecurityContextConstraints,
	opts metav1.PatchOptions,
) (*api.SecurityContextConstraints, kutil.VerbType, error) {
	return PatchSecurityContextConstraintsObject(ctx, c, cur, transform(cur.DeepCopy()), opts)
}

func PatchSecurityContextConstraintsObject(
	ctx context.Context,
	c cs.Interface,
	cur, mod *api.SecurityContextConstraints,
	opts metav1.PatchOptions,
) (*api.SecurityContextConstraints, kutil.VerbType, error) {
	curJson, err := json.Marshal(cur)
	if err != nil {
		return nil, kutil.VerbUnchanged, err
	}

	modJson, err := json.Marshal(mod)
	if err != nil {
		return nil, kutil.VerbUnchanged, err
	}

	patch, err := strategicpatch.CreateTwoWayMergePatch(curJson, modJson, api.SecurityContextConstraints{})
	if err != nil {
		return nil, kutil.VerbUnchanged, err
	}
	if len(patch) == 0 || string(patch) == "{}" {
		return cur, kutil.VerbUnchanged, nil
	}
	glog.V(3).Infof("Patching SecurityContextConstraints %s with %s.", cur.Name, string(patch))
	out, err := c.SecurityV1().SecurityContextConstraints().Patch(ctx, cur.Name, types.StrategicMergePatchType, patch, opts)
	return out, kutil.VerbPatched, err
}

func TryUpdateSecurityContextConstraints(
	ctx context.Context,
	c cs.Interface,
	meta metav1.ObjectMeta,
	transform func(*api.SecurityContextConstraints) *api.SecurityContextConstraints,
	opts metav1.UpdateOptions,
) (result *api.SecurityContextConstraints, err error) {
	attempt := 0
	err = wait.PollImmediate(kutil.RetryInterval, kutil.RetryTimeout, func() (bool, error) {
		attempt++
		cur, e2 := c.SecurityV1().SecurityContextConstraints().Get(ctx, meta.Name, metav1.GetOptions{})
		if kerr.IsNotFound(e2) {
			return false, e2
		} else if e2 == nil {
			result, e2 = c.SecurityV1().SecurityContextConstraints().Update(ctx, transform(cur.DeepCopy()), opts)
			return e2 == nil, nil
		}
		glog.Errorf("Attempt %d failed to update SecurityContextConstraints %s due to %v.", attempt, cur.Name, e2)
		return false, nil
	})

	if err != nil {
		err = errors.Errorf("failed to update SecurityContextConstraints %s after %d attempts due to %v", meta.Name, attempt, err)
	}
	return
}
