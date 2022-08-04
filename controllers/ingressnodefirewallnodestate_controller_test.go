package controllers

import (
	"context"
	"fmt"
	"sync"
	"time"

	infv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// mockFirewallRequestSyncer defines a struct that will serve as a  mock replacement for
// syncIngressNodeFirewallResources.
type mockFirewallRequestSyncer struct {
	calledCount int
	mu          sync.Mutex
}

func (m *mockFirewallRequestSyncer) getCalledCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.calledCount
}

// syncIngressNodeFirewallResources implements a mock for the function of the same name.
func (m *mockFirewallRequestSyncer) syncIngressNodeFirewallResources(r *IngressNodeFirewallNodeStateReconciler, instance *infv1alpha1.IngressNodeFirewallNodeState, isDelete bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	logger := r.Log.WithName("syncIngressNodeFirewallResourcesMock")
	logger.Info("Starting the mock reconciler")
	m.calledCount++
	logger.Info("Increased call count", "calledCount", m.calledCount)
	return nil
}

var mockSyncer *mockFirewallRequestSyncer

func init() {
	// replace syncIngressNodeFirewallResources with a suitable mock for testing.
	if mockSyncer == nil {
		mockSyncer = &mockFirewallRequestSyncer{}
	}
	syncIngressNodeFirewallResources = mockSyncer.syncIngressNodeFirewallResources
}

var _ = Describe("IngressNodeFirewallNodeState controller", func() {
	const (
		timeout  = time.Second * 10
		interval = time.Millisecond * 250
	)

	ctx := context.Background()
	BeforeEach(func() {
		By(fmt.Sprintf("By creating a new Node object with name %s", daemonReconcilerNodeName))
		node := v1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: daemonReconcilerNodeName,
			},
		}
		Expect(k8sClient.Create(ctx, &node)).Should(Succeed())

		By(fmt.Sprintf("By creating a new IngressNodeFirewallNodeState object for node %s", daemonReconcilerNodeName))
		rules := []infv1alpha1.IngressNodeFirewallRules{
			{
				SourceCIDRs: []string{"10.0.0.0"},
				FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
					{
						Order: 10,
						ProtocolRule: &infv1alpha1.IngressNodeFirewallProtoRule{
							Ports: "80",
						},
						ICMPRule: &infv1alpha1.IngressNodeFirewallICMPRule{},
						Protocol: "tcp",
						Action:   "allow",
					},
				},
			},
		}
		interfaces := []string{"eth0"}
		ingressNodeFirewall := infv1alpha1.IngressNodeFirewallNodeState{
			TypeMeta:   metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{Name: daemonReconcilerNodeName, Namespace: IngressNodeFwConfigTestNameSpace},
			Spec: infv1alpha1.IngressNodeFirewallNodeStateSpec{
				Ingress:    rules,
				Interfaces: &interfaces,
			},
		}
		Expect(k8sClient.Create(ctx, &ingressNodeFirewall)).Should(Succeed())
	})

	AfterEach(func() {
		Expect(k8sClient.DeleteAllOf(context.Background(), &infv1alpha1.IngressNodeFirewall{})).Should(Succeed())
		Expect(k8sClient.DeleteAllOf(context.Background(), &v1.Node{})).Should(Succeed())
		Expect(k8sClient.DeleteAllOf(
			context.Background(),
			&infv1alpha1.IngressNodeFirewallNodeState{},
			client.InNamespace(IngressNodeFwConfigTestNameSpace))).Should(Succeed())
	})

	// Baseline test.
	When(fmt.Sprintf("an IngressNodeFirewallNodeState object is created that matches node name %s", daemonReconcilerNodeName), func() {
		It(fmt.Sprintf("eBPF rule reconciliation for node %s should be triggered", daemonReconcilerNodeName), func() {
			By("By checking that the reconciler was called")
			Eventually(func() bool {
				return mockSyncer.getCalledCount() > 0
			}, timeout, interval).Should(BeTrue())
		})
	})
})
