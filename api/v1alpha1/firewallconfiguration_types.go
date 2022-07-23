/*
Copyright 2022.

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

package v1alpha1

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// FirewallConfigurationSpec defines the desired state of FirewallConfiguration
type FirewallConfigurationSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// The image that will we used for the DaemonSet pods.
	FirewallControllerImage *string `json:"firewallControllerImage"`
	// This directly sets the Affinity of the pods that the firewall DaemonSet will run on.
	// +optional
	Affinity *v1.Affinity `json:"affinity"`

	// This directly sets the NodeSelector of the pods that the firewall DaemonSet will run on.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector"`
}

// FirewallConfigurationStatus defines the observed state of FirewallConfiguration
type FirewallConfigurationStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// An indicator that informs about the successful deployment of all DaemonSet
	// pods.
	Deployed *bool `json:"deployed"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// FirewallConfiguration is the Schema for the firewallconfigurations API
type FirewallConfiguration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   FirewallConfigurationSpec   `json:"spec,omitempty"`
	Status FirewallConfigurationStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// FirewallConfigurationList contains a list of FirewallConfiguration
type FirewallConfigurationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FirewallConfiguration `json:"items"`
}

func init() {
	SchemeBuilder.Register(&FirewallConfiguration{}, &FirewallConfigurationList{})
}
