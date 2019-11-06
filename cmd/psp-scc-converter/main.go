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
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"kmodules.xyz/client-go/meta"
	scc "kmodules.xyz/openshift/apis/security/v1"
	api "kmodules.xyz/security-policy-api/apis/policy/v1beta1"
	pc "kmodules.xyz/security-policy-api/client/policy/v1beta1"

	policy "k8s.io/api/policy/v1beta1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatalln("correct usage: psp-scc-converter path-to-psp/scc-file")
	}

	filepath := os.Args[1]
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		log.Fatalln(err)
	}
	data, err = yaml.JSONToYAML(data)
	if err != nil {
		log.Fatalln(err)
	}

	var u unstructured.Unstructured
	err = yaml.Unmarshal(data, &u)
	if err != nil {
		log.Fatalln(err)
	}

	switch u.GetObjectKind().GroupVersionKind() {
	case policy.SchemeGroupVersion.WithKind(api.KindPodSecurityPolicy):
		in, err := meta.UnmarshalFromYAML(data, policy.SchemeGroupVersion)
		if err != nil {
			log.Fatalln(err)
		}
		sp, err := pc.ConvertToSecurityPolicy(in)
		if err != nil {
			log.Fatalln(err)
		}
		sc := pc.ToSecurityContextConstraints(sp)
		out, err := meta.MarshalToYAML(sc, scc.GroupVersion)
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Println(string(out))
	case scc.GroupVersion.WithKind(api.KindSecurityContextConstraints):
		in, err := meta.UnmarshalFromYAML(data, scc.GroupVersion)
		if err != nil {
			log.Fatalln(err)
		}
		sp, err := pc.ConvertToSecurityPolicy(in)
		if err != nil {
			log.Fatalln(err)
		}
		sc := pc.ToPodSecurityPolicy(sp)
		out, err := meta.MarshalToYAML(sc, policy.SchemeGroupVersion)
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Println(string(out))
	default:
		log.Fatalln("unknown or unsupported GroupVersionKind found in input file.")
	}
}
