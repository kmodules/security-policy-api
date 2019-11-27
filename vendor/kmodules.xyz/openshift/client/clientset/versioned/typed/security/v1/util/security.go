package util

import (
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

func CreateOrPatchSecurityContextConstraints(c cs.Interface, meta metav1.ObjectMeta, transform func(*api.SecurityContextConstraints) *api.SecurityContextConstraints) (*api.SecurityContextConstraints, kutil.VerbType, error) {
	cur, err := c.SecurityV1().SecurityContextConstraints().Get(meta.Name, metav1.GetOptions{})
	if kerr.IsNotFound(err) {
		glog.V(3).Infof("Creating SecurityContextConstraints %s/%s.", meta.Namespace, meta.Name)
		out, err := c.SecurityV1().SecurityContextConstraints().Create(transform(&api.SecurityContextConstraints{
			TypeMeta: metav1.TypeMeta{
				Kind:       "SecurityContextConstraints",
				APIVersion: api.SchemeGroupVersion.String(),
			},
			ObjectMeta: meta,
		}))
		return out, kutil.VerbCreated, err
	} else if err != nil {
		return nil, kutil.VerbUnchanged, err
	}
	return PatchSecurityContextConstraints(c, cur, transform)
}

func PatchSecurityContextConstraints(c cs.Interface, cur *api.SecurityContextConstraints, transform func(*api.SecurityContextConstraints) *api.SecurityContextConstraints) (*api.SecurityContextConstraints, kutil.VerbType, error) {
	return PatchSecurityContextConstraintsObject(c, cur, transform(cur.DeepCopy()))
}

func PatchSecurityContextConstraintsObject(c cs.Interface, cur, mod *api.SecurityContextConstraints) (*api.SecurityContextConstraints, kutil.VerbType, error) {
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
	out, err := c.SecurityV1().SecurityContextConstraints().Patch(cur.Name, types.StrategicMergePatchType, patch)
	return out, kutil.VerbPatched, err
}

func TryUpdateSecurityContextConstraints(c cs.Interface, meta metav1.ObjectMeta, transform func(*api.SecurityContextConstraints) *api.SecurityContextConstraints) (result *api.SecurityContextConstraints, err error) {
	attempt := 0
	err = wait.PollImmediate(kutil.RetryInterval, kutil.RetryTimeout, func() (bool, error) {
		attempt++
		cur, e2 := c.SecurityV1().SecurityContextConstraints().Get(meta.Name, metav1.GetOptions{})
		if kerr.IsNotFound(e2) {
			return false, e2
		} else if e2 == nil {
			result, e2 = c.SecurityV1().SecurityContextConstraints().Update(transform(cur.DeepCopy()))
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
