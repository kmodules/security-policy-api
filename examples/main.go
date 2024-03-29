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
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	api "kmodules.xyz/security-policy-api/apis/policy/v1beta1"
	pc "kmodules.xyz/security-policy-api/client/policy/v1beta1"

	policy "k8s.io/api/policy/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func main() {
	masterURL := ""
	kubeconfigPath := filepath.Join(homedir.HomeDir(), ".kube", "config")

	config, err := clientcmd.BuildConfigFromFlags(masterURL, kubeconfigPath)
	if err != nil {
		log.Fatalf("Could not get Kubernetes config: %s", err)
	}
	client, err := pc.NewForConfig(config)
	if err != nil {
		log.Fatalln(err)
	}

	/*
		apiVersion: policy/v1beta1
		kind: PodSecurityPolicy
		metadata:
		  name: example
		spec:
		  privileged: false  # Don't allow privileged pods!
		  # The rest fills in some required fields.
		  seLinux:
		    rule: RunAsAny
		  supplementalGroups:
		    rule: RunAsAny
		  runAsUser:
		    rule: RunAsAny
		  fsGroup:
		    rule: RunAsAny
		  volumes:
		  - '*'
	*/
	s1 := api.SecurityPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "demo-psp7",
		},
		Spec: api.SecurityPolicySpec{
			PodSecurityPolicySpec: policy.PodSecurityPolicySpec{
				Privileged: false,
				SELinux: policy.SELinuxStrategyOptions{
					Rule: policy.SELinuxStrategyRunAsAny,
				},
				SupplementalGroups: policy.SupplementalGroupsStrategyOptions{
					Rule: policy.SupplementalGroupsStrategyRunAsAny,
				},
				RunAsUser: policy.RunAsUserStrategyOptions{
					Rule: policy.RunAsUserStrategyRunAsAny,
				},
				FSGroup: policy.FSGroupStrategyOptions{
					Rule: policy.FSGroupStrategyRunAsAny,
				},
				Volumes: []policy.FSType{
					policy.All,
				},
				AllowedHostPaths: []policy.AllowedHostPath{
					{
						PathPrefix: "/etc",
						ReadOnly:   true,
					},
				},
			},
		},
	}
	s2, err := client.SecurityPolicies().Create(context.TODO(), &s1, metav1.CreateOptions{})
	if err != nil {
		fmt.Println("ERROR", err)
		os.Exit(1)
	}

	s3, kt, err := client.SecurityPolicies().Patch(context.TODO(), s2, func(in *api.SecurityPolicy) *api.SecurityPolicy {
		in.Spec.Privileged = true
		return in
	}, metav1.PatchOptions{})
	if err != nil {
		fmt.Println("ERROR", err)
		os.Exit(1)
	}
	fmt.Println(s3, kt)

	list, err := client.SecurityPolicies().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		fmt.Println("ERROR", err)
		os.Exit(1)
	}
	fmt.Println(list)

	err = client.SecurityPolicies().Delete(context.TODO(), s3, metav1.DeleteOptions{})
	if err != nil {
		fmt.Println("ERROR", err)
		os.Exit(1)
	}
}
