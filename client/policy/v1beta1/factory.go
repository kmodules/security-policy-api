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
	"fmt"
	"math"

	scc "kmodules.xyz/openshift/apis/security/v1"
	api "kmodules.xyz/security-policy-api/apis/policy/v1beta1"

	"github.com/appscode/go/types"
	policy "k8s.io/api/policy/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/integer"
)

func ConvertToSecurityPolicy(obj runtime.Object) (*api.SecurityPolicy, error) {
	switch t := obj.(type) {
	case *policy.PodSecurityPolicy:
		return FromPodSecurityPolicy(t), nil
	case *scc.SecurityContextConstraints:
		return FromSecurityContextConstraints(t), nil
	default:
		return nil, fmt.Errorf("the object is not a security policy")
	}
}

func ToPodSecurityPolicy(in *api.SecurityPolicy) *policy.PodSecurityPolicy {
	if in == nil {
		return nil
	}
	return &policy.PodSecurityPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: policy.SchemeGroupVersion.String(),
			Kind:       api.KindPodSecurityPolicy,
		},
		ObjectMeta: in.ObjectMeta,
		Spec:       in.Spec.PodSecurityPolicySpec,
	}
}

func FromPodSecurityPolicy(in *policy.PodSecurityPolicy) *api.SecurityPolicy {
	if in == nil {
		return nil
	}
	return &api.SecurityPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: policy.SchemeGroupVersion.String(),
			Kind:       api.KindPodSecurityPolicy,
		},
		ObjectMeta: in.ObjectMeta,
		Spec: api.SecurityPolicySpec{
			PodSecurityPolicySpec: in.Spec,
		},
	}
}

func ToSecurityContextConstraints(in *api.SecurityPolicy) *scc.SecurityContextConstraints {
	if in == nil {
		return nil
	}
	return &scc.SecurityContextConstraints{
		TypeMeta: metav1.TypeMeta{
			APIVersion: scc.GroupVersion.String(),
			Kind:       api.KindSecurityContextConstraints,
		},
		ObjectMeta: in.ObjectMeta,

		AllowedCapabilities:             in.Spec.AllowedCapabilities,
		AllowedFlexVolumes:              toAllowedFlexVolumes(in.Spec.AllowedFlexVolumes),
		AllowedUnsafeSysctls:            in.Spec.AllowedUnsafeSysctls,
		AllowHostDirVolumePlugin:        len(in.Spec.AllowedHostPaths) > 0,
		AllowHostIPC:                    in.Spec.HostIPC,
		AllowHostNetwork:                in.Spec.HostNetwork,
		AllowHostPID:                    in.Spec.HostPID,
		AllowHostPorts:                  len(in.Spec.HostPorts) > 0,
		AllowPrivilegedContainer:        in.Spec.Privileged,
		AllowPrivilegeEscalation:        in.Spec.AllowPrivilegeEscalation,
		DefaultAddCapabilities:          in.Spec.DefaultAddCapabilities,
		DefaultAllowPrivilegeEscalation: in.Spec.DefaultAllowPrivilegeEscalation,
		ForbiddenSysctls:                in.Spec.ForbiddenSysctls,
		FSGroup:                         toFSGroupStrategyOptions(in.Spec.FSGroup),
		Groups:                          in.Spec.Groups,
		Priority:                        in.Spec.Priority,
		ReadOnlyRootFilesystem:          in.Spec.ReadOnlyRootFilesystem,
		RequiredDropCapabilities:        in.Spec.RequiredDropCapabilities,
		RunAsUser:                       toRunAsUserStrategyOptions(in.Spec.RunAsUser),
		SeccompProfiles:                 in.Spec.SeccompProfiles,
		SELinuxContext:                  toSELinuxContextStrategyOptions(in.Spec.SELinux),
		SupplementalGroups:              toSupplementalGroupsStrategyOptions(in.Spec.SupplementalGroups),
		Users:                           in.Spec.Users,
		Volumes:                         toFSTypes(in.Spec.Volumes),
	}
}

func FromSecurityContextConstraints(in *scc.SecurityContextConstraints) *api.SecurityPolicy {
	if in == nil {
		return nil
	}
	return &api.SecurityPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: scc.GroupVersion.String(),
			Kind:       api.KindSecurityContextConstraints,
		},
		ObjectMeta: in.ObjectMeta,
		Spec: api.SecurityPolicySpec{
			PodSecurityPolicySpec: policy.PodSecurityPolicySpec{
				AllowedCapabilities:             in.AllowedCapabilities,
				AllowedFlexVolumes:              fromAllowedFlexVolumes(in.AllowedFlexVolumes),
				AllowedUnsafeSysctls:            in.AllowedUnsafeSysctls,
				AllowedHostPaths:                fromAllowHostDirVolumePlugin(in.AllowHostDirVolumePlugin),
				HostIPC:                         in.AllowHostIPC,
				HostNetwork:                     in.AllowHostNetwork,
				HostPID:                         in.AllowHostPID,
				HostPorts:                       fromAllowHostPorts(in.AllowHostPorts),
				AllowPrivilegeEscalation:        in.AllowPrivilegeEscalation,
				DefaultAddCapabilities:          in.DefaultAddCapabilities,
				DefaultAllowPrivilegeEscalation: in.DefaultAllowPrivilegeEscalation,
				ForbiddenSysctls:                in.ForbiddenSysctls,
				FSGroup:                         fromFSGroupStrategyOptions(in.FSGroup),
				Privileged:                      in.AllowPrivilegedContainer,
				ReadOnlyRootFilesystem:          in.ReadOnlyRootFilesystem,
				RequiredDropCapabilities:        in.RequiredDropCapabilities,
				RunAsUser:                       fromRunAsUserStrategyOptions(in.RunAsUser),
				SELinux:                         fromSELinuxContextStrategyOptions(in.SELinuxContext),
				SupplementalGroups:              fromSupplementalGroupsStrategyOptions(in.SupplementalGroups),
				Volumes:                         fromFSTypes(in.Volumes),
			},
			Groups:          in.Groups,
			Priority:        in.Priority,
			SeccompProfiles: in.SeccompProfiles,
			Users:           in.Users,
		},
	}
}

func fromAllowHostDirVolumePlugin(allowHostDirVolumePlugin bool) []policy.AllowedHostPath {
	if allowHostDirVolumePlugin {
		return []policy.AllowedHostPath{}
	}
	return []policy.AllowedHostPath{
		// making a safe bet that it is ok to read /tmp files
		{
			PathPrefix: "/tmp",
			ReadOnly:   true,
		},
	}
}

func fromAllowHostPorts(allowHostPorts bool) []policy.HostPortRange {
	if !allowHostPorts {
		return nil
	}
	return []policy.HostPortRange{
		{
			Min: 0,
			Max: 65535,
		},
	}
}

func toAllowedFlexVolumes(in []policy.AllowedFlexVolume) []scc.AllowedFlexVolume {
	out := make([]scc.AllowedFlexVolume, 0, len(in))
	for _, x := range in {
		out = append(out, scc.AllowedFlexVolume{
			Driver: x.Driver,
		})
	}
	return out
}

func fromAllowedFlexVolumes(in []scc.AllowedFlexVolume) []policy.AllowedFlexVolume {
	out := make([]policy.AllowedFlexVolume, 0, len(in))
	for _, x := range in {
		out = append(out, policy.AllowedFlexVolume{
			Driver: x.Driver,
		})
	}
	return out
}

func toFSGroupStrategyOptions(in policy.FSGroupStrategyOptions) scc.FSGroupStrategyOptions {
	return scc.FSGroupStrategyOptions{
		Type:   scc.FSGroupStrategyType(string(in.Rule)),
		Ranges: toIDRange(in.Ranges),
	}
}

func fromFSGroupStrategyOptions(in scc.FSGroupStrategyOptions) policy.FSGroupStrategyOptions {
	return policy.FSGroupStrategyOptions{
		Rule:   policy.FSGroupStrategyType(string(in.Type)),
		Ranges: fromIDRange(in.Ranges),
	}
}

func toIDRange(in []policy.IDRange) []scc.IDRange {
	out := make([]scc.IDRange, 0, len(in))
	for _, x := range in {
		out = append(out, scc.IDRange{
			Min: x.Min,
			Max: x.Max,
		})
	}
	return out
}

func fromIDRange(in []scc.IDRange) []policy.IDRange {
	out := make([]policy.IDRange, 0, len(in))
	for _, x := range in {
		out = append(out, policy.IDRange{
			Min: x.Min,
			Max: x.Max,
		})
	}
	return out
}

func toRunAsUserStrategyOptions(in policy.RunAsUserStrategyOptions) scc.RunAsUserStrategyOptions {
	var out scc.RunAsUserStrategyOptions

	out.Type = scc.RunAsUserStrategyType(string(in.Rule))
	if len(in.Ranges) == 1 {
		if in.Ranges[0].Min == in.Ranges[0].Max {
			out.UID = types.Int64P(in.Ranges[0].Min)
		} else {
			out.Type = scc.RunAsUserStrategyMustRunAsRange
			out.UIDRangeMin = types.Int64P(in.Ranges[0].Min)
			out.UIDRangeMax = types.Int64P(in.Ranges[0].Max)
		}
	} else if len(in.Ranges) > 1 {
		var min int64 = math.MaxInt64
		var max int64 = math.MinInt64
		for _, x := range in.Ranges {
			min = integer.Int64Min(min, x.Min)
			max = integer.Int64Max(max, x.Max)
		}

		if min == max {
			out.UID = types.Int64P(min)
		} else {
			out.Type = scc.RunAsUserStrategyMustRunAsRange
			out.UIDRangeMin = types.Int64P(min)
			out.UIDRangeMax = types.Int64P(max)
		}
	}
	return out
}

func fromRunAsUserStrategyOptions(in scc.RunAsUserStrategyOptions) policy.RunAsUserStrategyOptions {
	var out policy.RunAsUserStrategyOptions

	out.Rule = policy.RunAsUserStrategy(string(in.Type))
	if in.UID != nil {
		out.Ranges = []policy.IDRange{
			{
				Min: *in.UID,
				Max: *in.UID,
			},
		}
	} else if in.UIDRangeMin != nil && in.UIDRangeMax != nil {
		out.Ranges = []policy.IDRange{
			{
				Min: *in.UIDRangeMin,
				Max: *in.UIDRangeMax,
			},
		}
	}
	return out
}

func toSELinuxContextStrategyOptions(in policy.SELinuxStrategyOptions) scc.SELinuxContextStrategyOptions {
	return scc.SELinuxContextStrategyOptions{
		Type:           scc.SELinuxContextStrategyType(string(in.Rule)),
		SELinuxOptions: in.SELinuxOptions,
	}
}

func fromSELinuxContextStrategyOptions(in scc.SELinuxContextStrategyOptions) policy.SELinuxStrategyOptions {
	return policy.SELinuxStrategyOptions{
		Rule:           policy.SELinuxStrategy(string(in.Type)),
		SELinuxOptions: in.SELinuxOptions,
	}
}

func toSupplementalGroupsStrategyOptions(in policy.SupplementalGroupsStrategyOptions) scc.SupplementalGroupsStrategyOptions {
	if in.Rule == policy.SupplementalGroupsStrategyMayRunAs {
		panic("unsupported")
	}
	return scc.SupplementalGroupsStrategyOptions{
		Type:   scc.SupplementalGroupsStrategyType(string(in.Rule)),
		Ranges: toIDRange(in.Ranges),
	}
}

func fromSupplementalGroupsStrategyOptions(in scc.SupplementalGroupsStrategyOptions) policy.SupplementalGroupsStrategyOptions {
	return policy.SupplementalGroupsStrategyOptions{
		Rule:   policy.SupplementalGroupsStrategyType(string(in.Type)),
		Ranges: fromIDRange(in.Ranges),
	}
}

func toFSTypes(in []policy.FSType) []scc.FSType {
	out := make([]scc.FSType, 0, len(in))
	for _, x := range in {
		out = append(out, scc.FSType(string(x)))
	}
	return out
}

func fromFSTypes(in []scc.FSType) []policy.FSType {
	out := make([]policy.FSType, 0, len(in))
	for _, x := range in {
		out = append(out, policy.FSType(string(x)))
	}
	return out
}
