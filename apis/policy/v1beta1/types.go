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
	policy "k8s.io/api/policy/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SecurityPolicy governs the ability to make requests that affect the Security Context
// that will be applied to a pod and container.
type SecurityPolicy struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	// More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec defines the policy enforced.
	// +optional
	Spec SecurityPolicySpec `json:"spec,omitempty"`
}

// SecurityPolicySpec defines the policy enforced.
type SecurityPolicySpec struct {
	policy.PodSecurityPolicySpec `json:",inline"`

	// -----------------------------------------------------------------------------------------------------------------

	// The users who have permissions to use this security context constraints
	// +optional
	// +nullable
	Users []string `json:"users"`
	// The groups that have permission to use this security context constraints
	// +optional
	// +nullable
	Groups []string `json:"groups"`

	// SeccompProfiles lists the allowed profiles that may be set for the pod or
	// container's seccomp annotations.  An unset (nil) or empty value means that no profiles may
	// be specifid by the pod or container.	The wildcard '*' may be used to allow all profiles.  When
	// used to generate a value for a pod the first non-wildcard profile will be used as
	// the default.
	SeccompProfiles []string `json:"seccompProfiles,omitempty"`

	// Priority influences the sort order of SCCs when evaluating which SCCs to try first for
	// a given pod request based on access in the Users and Groups fields.  The higher the int, the
	// higher priority. An unset value is considered a 0 priority. If scores
	// for multiple SCCs are equal they will be sorted from most restrictive to
	// least restrictive. If both priorities and restrictions are equal the
	// SCCs will be sorted by name.
	Priority *int32 `json:"priority"`

	// AllowHostDirVolumePlugin bool if len(AllowedHostPaths) > 0
	// AllowHostPorts bool if len(HostPorts) > 0
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SecurityPolicyList is a list of SecurityPolicy objects.
type SecurityPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard list metadata.
	// More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#metadata
	// +optional
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// items is a list of schema objects.
	Items []SecurityPolicy `json:"items" protobuf:"bytes,2,rep,name=items"`
}
