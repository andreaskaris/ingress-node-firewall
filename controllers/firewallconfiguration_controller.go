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

package controllers

import (
	"context"
	"reflect"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	ingressnodefwv1alpha1 "ingress-node-firewall/api/v1alpha1"
)

// FirewallConfigurationReconciler reconciles a FirewallConfiguration object
type FirewallConfigurationReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=ingress-nodefw.ingress-nodefw,resources=firewallconfigurations,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=ingress-nodefw.ingress-nodefw,resources=firewallconfigurations/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=ingress-nodefw.ingress-nodefw,resources=firewallconfigurations/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.1/pkg/reconcile
func (r *FirewallConfigurationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Get the FirewallConfiguration object.
	firewallConfiguration := &ingressnodefwv1alpha1.FirewallConfiguration{}
	err := r.Get(ctx, req.NamespacedName, firewallConfiguration)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			log.Info("FirewallConfiguration resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		log.Error(err, "Failed to get FirewallConfiguration")
		return ctrl.Result{}, err
	}

	// Get the DaemonSet - if it does not exist, create it according to the FirewallConfiguration.
	// Otherwise, update it if the FirewallConfiguration changed.
	daemonSet := &appsv1.DaemonSet{}
	err = r.Get(ctx, types.NamespacedName{Name: firewallConfiguration.Name, Namespace: firewallConfiguration.Namespace}, daemonSet)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating a new Daemonset", "Daemonset.Namespace", firewallConfiguration.Namespace, "Daemonset.Name", firewallConfiguration.Name)
		daemonSet = r.daemonSetForFirewallConfiguration(nil, firewallConfiguration)
		err = r.Create(ctx, daemonSet)
		if err != nil {
			log.Error(err, "Failed to create new DaemonSet", "Daemonset.Namespace", firewallConfiguration.Namespace, "Daemonset.Name", firewallConfiguration.Name)
			return ctrl.Result{}, err
		}
		// DaemonSet created successfully - return and requeue
		return ctrl.Result{Requeue: true}, nil
	} else if err != nil {
		log.Error(err, "Failed to get Daemonset", "Namespace", firewallConfiguration.Namespace, "Name", firewallConfiguration.Name)
		return ctrl.Result{}, err
	}

	// Update the DaemonSet with information from the FirewallConfiguration.
	if ds := r.daemonSetForFirewallConfiguration(daemonSet, firewallConfiguration); ds != nil {
		log.Info("Updating Daemonset", "Daemonset.Namespace", daemonSet.Namespace, "Daemonset.Name", daemonSet.Name)
		err = r.Update(ctx, daemonSet)
		if err != nil {
			log.Error(err, "Failed to update DaemonSet", "DaemonSet.Namespace", daemonSet.Namespace, "DaemonSet.Name", daemonSet.Name)
			return ctrl.Result{}, err
		}
		// Ask to requeue after 1 minute in order to give enough time for the
		// pods be created on the cluster side and the operand be able
		// to do the next update step accurately.
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *FirewallConfigurationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ingressnodefwv1alpha1.FirewallConfiguration{}).
		Owns(&appsv1.DaemonSet{}).
		Complete(r)
}

// daemonSetForFirewallConfiguration will create a new DaemonSet if ds is nil, or update a provided DaemonSet otherwise, according to the specification provided
// by fwc. In the case of an update, the returned memory location is the same as the provided memory location for ds. In case of an update, if no changes were  made
// to the spec, return nil.
func (r *FirewallConfigurationReconciler) daemonSetForFirewallConfiguration(ds *appsv1.DaemonSet, fwc *ingressnodefwv1alpha1.FirewallConfiguration) *appsv1.DaemonSet {
	if ds == nil {
		ds = &appsv1.DaemonSet{
			TypeMeta:   metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{Name: fwc.Name, Namespace: fwc.Namespace},
		}
	}

	// The label attached to the pods and with which the DaemonSet tracks pods that
	// it owns.
	dsLabel := map[string]string{"name": fwc.Name}
	// These tolerations are neede so that the firewall pods can also be spawned on the
	// control-plane nodes.
	tolerations := []v1.Toleration{
		{
			Key:      "node-role.kubernetes.io/control-plane",
			Operator: v1.TolerationOpExists,
			Effect:   v1.TaintEffectNoSchedule,
		},
		{
			Key:      "node-role.kubernetes.io/master",
			Operator: v1.TolerationOpExists,
			Effect:   v1.TaintEffectNoSchedule,
		},
	}
	container := v1.Container{
		Name:  fwc.Name,
		Image: *fwc.Spec.FirewallControllerImage,
		Command: []string{
			"sleep", "infinity",
		},
	}

	// The DaemonSet Spec - will be enforced on each reconciliation.
	spec := appsv1.DaemonSetSpec{
		Selector: &metav1.LabelSelector{
			MatchLabels:      dsLabel,
			MatchExpressions: []metav1.LabelSelectorRequirement{},
		},
		Template: v1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{
				Labels: dsLabel,
			},
			Spec: v1.PodSpec{
				Containers: []v1.Container{
					container,
				},
				NodeSelector: fwc.Spec.NodeSelector,
				Affinity:     fwc.Spec.Affinity,
				Tolerations:  tolerations,
			}},
	}

	// Only return a pointer to ds if the spec was updated (which of course if the case
	// for the newly created DaemonSet).
	if !reflect.DeepEqual(spec, ds.Spec) {
		ds.Spec = spec
		// Set FirewallConfiguration instance as the owner and controller
		ctrl.SetControllerReference(fwc, ds, r.Scheme)
		return ds
	}

	// Return nil if the old spec and the new spec are the same.
	return nil
}
