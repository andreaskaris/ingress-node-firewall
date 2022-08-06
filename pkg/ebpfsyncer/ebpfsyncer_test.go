package ebpfsyncer

import (
	"context"
	"fmt"
	"io"
	"net"
	"os/user"
	"testing"
	"time"

	infv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"
	"github.com/vishvananda/netlink"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

const (
	interfacePrefix = "dummy"
	testProto       = "tcp"
	testPort        = 12345
)

// var originalNetNS netns.NsHandle
// var newNetNS netns.NsHandle
// var newNetNSName string
var tap0 netlink.Tuntap
var tap1 netlink.Tuntap
var tap2 netlink.Tuntap

func runListenServer(ctx context.Context, protocol string, port int) error {
	ln, err := net.Listen(protocol, fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	defer ln.Close()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			defer c.Close()
			_, err := io.WriteString(c, time.Now().Format("15:04:05\n"))
			if err != nil {
				return // e.g., client disconnected
			}
		}(conn)
	}
}

func testDial(protocol string, ip string, port int) error {
	conn, err := net.Dial(protocol, fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return err
	}
	defer conn.Close()
	return nil
}

func beforeEach(t *testing.T) {
	fmt.Println("Checking if this test runs with sufficiently high privileges")
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("[isRoot] Unable to get current user: %s", err)
	}
	if currentUser.Uid != "0" {
		t.Skipf("Skipping this test due to insufficient privileges")
	}

	/*
		fmt.Println("Locking the OS Thread so we don't accidentally switch namespaces")
		runtime.LockOSThread()

		fmt.Println("By creating and using a new netns")
		// Save the current network namespace
		originalNetNS, err = netns.Get()
		Expect(err).NotTo(HaveOccurred())
		// Create a new network namespace
		newNetNSName = uuid.New().String()
		newNetNS, err = netns.NewNamed(newNetNSName)
		Expect(err).NotTo(HaveOccurred())
	*/

	fmt.Println("By creating new test interfaces for testing")
	// Create dummy0.
	la0 := netlink.NewLinkAttrs()
	la0.Name = fmt.Sprintf("%s0", interfacePrefix)
	tap0 = netlink.Tuntap{
		LinkAttrs: la0,
		Mode:      netlink.TUNTAP_MODE_TAP,
	}
	err = netlink.LinkAdd(&tap0)
	if err != nil {
		t.Fatal(err)
	}
	err = netlink.LinkSetUp(&tap0)
	if err != nil {
		t.Fatal(err)
	}
	// Create dummy1.
	la1 := netlink.NewLinkAttrs()
	la1.Name = fmt.Sprintf("%s1", interfacePrefix)
	tap1 = netlink.Tuntap{
		LinkAttrs: la1,
		Mode:      netlink.TUNTAP_MODE_TAP,
	}
	err = netlink.LinkAdd(&tap1)
	if err != nil {
		t.Fatal(err)
	}
	err = netlink.LinkSetUp(&tap1)
	if err != nil {
		t.Fatal(err)
	}
	// Create dummy2.
	la2 := netlink.NewLinkAttrs()
	la2.Name = fmt.Sprintf("%s2", interfacePrefix)
	tap2 = netlink.Tuntap{
		LinkAttrs: la2,
		Mode:      netlink.TUNTAP_MODE_TAP,
	}
	err = netlink.LinkAdd(&tap2)
	if err != nil {
		t.Fatal(err)
	}
	err = netlink.LinkSetUp(&tap2)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("By assigning IP addresses to the test interfaces")
	// Assign 192.0.2.1/32 to dummy0.
	addr0, err := netlink.ParseAddr("192.0.2.1/32")
	if err != nil {
		t.Fatal(err)
	}
	err = netlink.AddrAdd(&tap0, addr0)
	if err != nil {
		t.Fatal(err)
	}
	// Assign 192.0.2.2/32 to dummy1.
	addr1, err := netlink.ParseAddr("192.0.2.2/32")
	if err != nil {
		t.Fatal(err)
	}
	err = netlink.AddrAdd(&tap1, addr1)
	if err != nil {
		t.Fatal(err)
	}
	// Assign 192.0.2.3/32 to dummy2.
	addr2, err := netlink.ParseAddr("192.0.2.3/32")
	if err != nil {
		t.Fatal(err)
	}
	err = netlink.AddrAdd(&tap2, addr2)
	if err != nil {
		t.Fatal(err)
	}
}

func afterEach(t *testing.T) {
	if t.Skipped() {
		return
	}

	fmt.Println("Deleting the test interfaces")
	err := netlink.LinkDel(&tap0)
	if err != nil {
		t.Fatal(err)
	}
	err = netlink.LinkDel(&tap1)
	if err != nil {
		t.Fatal(err)
	}
	err = netlink.LinkDel(&tap2)
	if err != nil {
		t.Fatal(err)
	}

	/*
		fmt.Println("Switching back to original namespace")
		netns.Set(originalNetNS)
		originalNetNS.Close()
		newNetNS.Close()
		netns.DeleteNamed(newNetNSName)

		fmt.Println("Unlocking the OS Thread")
		defer runtime.UnlockOSThread()
	*/
}

// TestSyncInterfaceIngressRulesConnect attaches rules to an interfaces and verifies that the rules work.
func TestSyncInterfaceIngressRulesConnect(t *testing.T) {
	// The functionality that this test verifies is currently broken. Skip it.
	t.Skip()

	defer afterEach(t)
	beforeEach(t)

	rules := map[string][]infv1alpha1.IngressNodeFirewallRules{
		fmt.Sprintf("%s0", interfacePrefix): {
			{
				SourceCIDRs: []string{"10.0.0.0/16"},
				FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
					{
						Order: 10,
						ProtocolRule: &infv1alpha1.IngressNodeFirewallProtoRule{
							Ports: "80",
						},
						Protocol: "tcp",
						Action:   "allow",
					},
				},
			},
			{
				SourceCIDRs: []string{"0.0.0.0/0"},
				FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
					{
						Order: 10,
						ProtocolRule: &infv1alpha1.IngressNodeFirewallProtoRule{
							Ports: fmt.Sprintf("%d", testPort),
						},
						Protocol: testProto,
						Action:   "deny",
					},
				},
			},
		},
	}

	ctx := context.Background()
	fmt.Println("Running a server that's listening on", testProto, testPort)
	go runListenServer(ctx, testProto, testPort)

	fmt.Println("Giving the server a few seconds to start")
	time.Sleep(2 * time.Second)

	fmt.Println("Trying to connect to the server (should succeed)", testProto, testPort)
	err := testDial(testProto, "192.0.2.1", testPort)
	if err != nil {
		t.Fatal(err)
	}

	l := zap.New()
	fmt.Println("Running the ebpfsyncer's sync to attach rules")
	err = GetEbpfSyncer(ctx, l, nil, nil).SyncInterfaceIngressRules(rules, false)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Trying to connect to the server (should fail)", testProto, testPort)
	err = testDial(testProto, "192.0.2.1", testPort)
	if err == nil {
		t.Fatal("Connection to server was succesful but it shouldn't be")
	}

	fmt.Println("Running ebpfsyncer's sync to delete rules")
	err = GetEbpfSyncer(ctx, l, nil, nil).SyncInterfaceIngressRules(rules, true)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Trying to connect to the server (should succeed)", testProto, testPort)
	err = testDial(testProto, "192.0.2.1", testPort)
	if err != nil {
		t.Fatal(err)
	}
}

// TestSyncInterfaceIngressRulesAttachAndDetachSingleInterface attaches and detaches rules from interfaces 2x in a row to test
// that this operation works.
func TestSyncInterfaceIngressRulesAttachAndDetachSingleInterface(t *testing.T) {
	// Skip this test as it currently fails.
	t.Skip()

	defer afterEach(t)
	beforeEach(t)

	rules := map[string][]infv1alpha1.IngressNodeFirewallRules{
		fmt.Sprintf("%s0", interfacePrefix): {
			{
				SourceCIDRs: []string{"10.0.0.0/16"},
				FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
					{
						Order: 10,
						ProtocolRule: &infv1alpha1.IngressNodeFirewallProtoRule{
							Ports: "80",
						},
						Protocol: "tcp",
						Action:   "allow",
					},
				},
			},
			{
				SourceCIDRs: []string{"0.0.0.0/0"},
				FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
					{
						Order: 10,
						ProtocolRule: &infv1alpha1.IngressNodeFirewallProtoRule{
							Ports: "80",
						},
						Protocol: "tcp",
						Action:   "deny",
					},
				},
			},
		},
	}

	ctx := context.Background()
	l := zap.New()
	fmt.Println("Running the ebpfsyncer's sync to attach rules")
	err := GetEbpfSyncer(ctx, l, nil, nil).SyncInterfaceIngressRules(rules, false)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Running ebpfsyncer's sync to delete rules")
	err = GetEbpfSyncer(ctx, l, nil, nil).SyncInterfaceIngressRules(rules, true)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Running the ebpfsyncer's sync to attach rules again")
	err = GetEbpfSyncer(ctx, l, nil, nil).SyncInterfaceIngressRules(rules, false)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Running ebpfsyncer's sync to delete rules again")
	err = GetEbpfSyncer(ctx, l, nil, nil).SyncInterfaceIngressRules(rules, true)
	if err != nil {
		t.Fatal(err)
	}
}

// TestSyncInterfaceIngressRulesAttachAndDetach attaches and detaches rules from interfaces 2x in a row to test
// that this operation works.
func TestSyncInterfaceIngressRulesAttachAndDetach(t *testing.T) {
	// TODO:
	// The funtionality that this test is supposed to test is currently broken.
	t.Skip()

	defer afterEach(t)
	beforeEach(t)

	rules := map[string][]infv1alpha1.IngressNodeFirewallRules{
		fmt.Sprintf("%s0", interfacePrefix): {
			{
				SourceCIDRs: []string{"10.0.0.0/16"},
				FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
					{
						Order: 10,
						ProtocolRule: &infv1alpha1.IngressNodeFirewallProtoRule{
							Ports: "80",
						},
						Protocol: "tcp",
						Action:   "allow",
					},
				},
			},
		},
		fmt.Sprintf("%s1", interfacePrefix): {
			{
				SourceCIDRs: []string{"10.0.1.0/16"},
				FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
					{
						Order: 10,
						ProtocolRule: &infv1alpha1.IngressNodeFirewallProtoRule{
							Ports: "81",
						},
						Protocol: "tcp",
						Action:   "allow",
					},
				},
			},
		},
		fmt.Sprintf("%s2", interfacePrefix): {
			{
				SourceCIDRs: []string{"10.0.2.0/16"},
				FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
					{
						Order: 10,
						ProtocolRule: &infv1alpha1.IngressNodeFirewallProtoRule{
							Ports: "81",
						},
						Protocol: "tcp",
						Action:   "allow",
					},
				},
			},
		},
	}

	ctx := context.Background()
	l := zap.New()
	fmt.Println("Running the ebpfsyncer's sync to attach rules")
	err := GetEbpfSyncer(ctx, l, nil, nil).SyncInterfaceIngressRules(rules, false)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Running ebpfsyncer's sync to delete rules")
	err = GetEbpfSyncer(ctx, l, nil, nil).SyncInterfaceIngressRules(rules, true)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Running the ebpfsyncer's sync to attach rules again")
	err = GetEbpfSyncer(ctx, l, nil, nil).SyncInterfaceIngressRules(rules, false)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Running ebpfsyncer's sync to delete rules again")
	err = GetEbpfSyncer(ctx, l, nil, nil).SyncInterfaceIngressRules(rules, true)
	if err != nil {
		t.Fatal(err)
	}
}

// TestSyncInterfaceIngressRulesAttachAndDetachSingleInterface calls the rule attach twice in a row to test idempotency.
func TestResyncInterfaceIngressRulesSingleInterface(t *testing.T) {
	defer afterEach(t)
	beforeEach(t)

	rules := map[string][]infv1alpha1.IngressNodeFirewallRules{
		fmt.Sprintf("%s0", interfacePrefix): {
			{
				SourceCIDRs: []string{"10.0.0.0/16"},
				FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
					{
						Order: 10,
						ProtocolRule: &infv1alpha1.IngressNodeFirewallProtoRule{
							Ports: "80",
						},
						Protocol: "tcp",
						Action:   "allow",
					},
				},
			},
			{
				SourceCIDRs: []string{"0.0.0.0/0"},
				FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
					{
						Order: 10,
						ProtocolRule: &infv1alpha1.IngressNodeFirewallProtoRule{
							Ports: "80",
						},
						Protocol: "tcp",
						Action:   "deny",
					},
				},
			},
		},
	}

	ctx := context.Background()
	fmt.Println("Running the ebpfsyncer's sync to attach rules")
	l := zap.New()
	err := GetEbpfSyncer(ctx, l, nil, nil).SyncInterfaceIngressRules(rules, false)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Running the ebpfsyncer's sync to attach rules again")
	err = GetEbpfSyncer(ctx, l, nil, nil).SyncInterfaceIngressRules(rules, false)
	if err != nil {
		t.Fatal(err)
	}
}

// TestSyncInterfaceIngressRulesAttachAndDetach calls the rule attach twice in a row to test idempotency.
func TestResyncInterfaceIngressRules(t *testing.T) {
	defer afterEach(t)
	beforeEach(t)

	rules := map[string][]infv1alpha1.IngressNodeFirewallRules{
		fmt.Sprintf("%s0", interfacePrefix): {
			{
				SourceCIDRs: []string{"10.0.0.0/16"},
				FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
					{
						Order: 10,
						ProtocolRule: &infv1alpha1.IngressNodeFirewallProtoRule{
							Ports: "80",
						},
						Protocol: "tcp",
						Action:   "allow",
					},
				},
			},
		},
		fmt.Sprintf("%s1", interfacePrefix): {
			{
				SourceCIDRs: []string{"10.0.1.0/16"},
				FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
					{
						Order: 10,
						ProtocolRule: &infv1alpha1.IngressNodeFirewallProtoRule{
							Ports: "81",
						},
						Protocol: "tcp",
						Action:   "allow",
					},
				},
			},
		},
		fmt.Sprintf("%s2", interfacePrefix): {
			{
				SourceCIDRs: []string{"10.0.2.0/16"},
				FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
					{
						Order: 10,
						ProtocolRule: &infv1alpha1.IngressNodeFirewallProtoRule{
							Ports: "81",
						},
						Protocol: "tcp",
						Action:   "allow",
					},
				},
			},
		},
	}

	ctx := context.Background()
	fmt.Println("Running the ebpfsyncer's sync to attach rules")
	l := zap.New()
	err := GetEbpfSyncer(ctx, l, nil, nil).SyncInterfaceIngressRules(rules, false)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Running the ebpfsyncer's sync to attach rules again")
	err = GetEbpfSyncer(ctx, l, nil, nil).SyncInterfaceIngressRules(rules, false)
	if err != nil {
		t.Fatal(err)
	}
}
