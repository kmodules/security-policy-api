package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	policy "k8s.io/api/policy/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	api "kmodules.xyz/security-policy-api/apis/policy/v1beta1"
	pc "kmodules.xyz/security-policy-api/client/policy/v1beta1"
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
	s2, err := client.SecurityPolicies().Create(&s1)
	if err != nil {
		fmt.Println("ERROR", err)
		os.Exit(1)
	}

	s3, kt, err := client.SecurityPolicies().Patch(s2, func(in *api.SecurityPolicy) *api.SecurityPolicy {
		in.Spec.Privileged = true
		return in
	})
	if err != nil {
		fmt.Println("ERROR", err)
		os.Exit(1)
	}
	fmt.Println(s3, kt)

	list, err := client.SecurityPolicies().List(metav1.ListOptions{})
	if err != nil {
		fmt.Println("ERROR", err)
		os.Exit(1)
	}
	fmt.Println(list)

	err = client.SecurityPolicies().Delete(s3, &metav1.DeleteOptions{})
	if err != nil {
		fmt.Println("ERROR", err)
		os.Exit(1)
	}
}
