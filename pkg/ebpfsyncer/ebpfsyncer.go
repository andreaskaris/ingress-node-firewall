package ebpfsyncer

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/go-logr/logr"
	infv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"
	nodefwloader "github.com/openshift/ingress-node-firewall/pkg/ebpf"
	"github.com/openshift/ingress-node-firewall/pkg/failsaferules"
	"github.com/openshift/ingress-node-firewall/pkg/metrics"
)

var once sync.Once
var instance EbpfSyncer

// ebpfDaemon is a single point of contact that all reconciliation requests will send their desired state of
// interface rules to. On the other side, ebpfDaemon makes sure that rules are attached and detached from / to the
// host's interfaces.
type EbpfSyncer interface {
	SyncInterfaceIngressRules(map[string][]infv1alpha1.IngressNodeFirewallRules, bool) error
}

// getEbpfDaemon allocates and returns a single instance of ebpfSingleton. If such an instance does not yet exist,
// it sets up a new one. It will do so only once. Then, it returns the instance.
func GetEbpfSyncer(ctx context.Context, log logr.Logger, stats *metrics.Statistics, mock EbpfSyncer) EbpfSyncer {
	once.Do(func() {
		// Check if instance is nil. For mock tests, one can provide a custom instance.
		if mock == nil {
			c, err := nodefwloader.NewIngNodeFwController()
			if err != nil {
				// TODO: Extremely unelegant. Fix this.
				panic(fmt.Errorf("Failed to create nodefw controller instance, err: %q", err))
			}

			instance = &ebpfSingleton{
				ctx:               ctx,
				log:               log,
				stats:             stats,
				managedInterfaces: make(map[string]struct{}),
				c:                 c,
			}
		} else {
			instance = mock
		}
	})
	return instance
}

// ebpfSingleton implements ebpfDaemon.
type ebpfSingleton struct {
	ctx               context.Context
	log               logr.Logger
	stats             *metrics.Statistics
	managedInterfaces map[string]struct{}
	c                 *nodefwloader.IngNodeFwController
	mu                sync.Mutex
}

// syncInterfaceIngressRules takes a map of <interfaceName>:<interfaceRules> and a boolean parameter that indicates
// if rules shall be attached to the interface or if rules shall be detached from the interface.
// If isDelete is true then all rules will be attached from all provided interfaces. In such a case, the given
// intefaceRules (if any) will be ignored.
// If isDelete is false then rules will be synchronized for each of the given interfaces.
func (e *ebpfSingleton) SyncInterfaceIngressRules(
	ifaceIngressRules map[string][]infv1alpha1.IngressNodeFirewallRules, isDelete bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	logger := e.log.WithName("SyncInterfaceIngressRules")
	logger.Info("Starting sync operation")

	if e.stats != nil {
		e.stats.StopPoll()
	}

	for ifaceName, rules := range ifaceIngressRules {
		var ifID uint32
		// Check if the interface is currently managed by us.
		_, ok := e.managedInterfaces[ifaceName]
		// If an interface is not managed yet, add it to the list of managed interfaces.
		// Then run an Unpin() just in case. This is needed in case the process crashed or could not clean up a
		// pin during a previous run.
		if !ok && !isDelete {
			e.managedInterfaces[ifaceName] = struct{}{}
			e.c.Unpin(ifaceName)
		}
		// Mark the interface as unmanaged if we get a delete request.
		if ok && isDelete {
			delete(e.managedInterfaces, ifaceName)
		}

		// Only attach to an interface if it is not managed yet.
		// Otherwise, we'd get "can't create link: device or resource busy".
		// Only detach from an interface if it is already managed.
		if !ok && !isDelete || ok && isDelete {
			logger.Info("Running attach / detach operation", "ifaceName", ifaceName, "isDelete", isDelete)
			ifList, err := e.c.IngressNodeFwAttach([]string{ifaceName}, isDelete)
			if err != nil {
				logger.Error(err, "Fail to attach / detach ingress firewall prog",
					"ifaceName", ifaceName, "isDelete", isDelete)
				return err
			}
			ifID = ifList[0]
		} else {
			// Look up the network interface by name otherwise.
			iface, err := net.InterfaceByName(ifaceName)
			if err != nil {
				return fmt.Errorf("lookup network iface %q: %s", ifaceName, err)
			}
			ifID = uint32(iface.Index)
		}

		for _, rule := range rules {
			rule := rule.DeepCopy()
			logger.Info("Adding failsafe rules", "ifaceName", ifaceName)
			if err := addFailSaferules(&rule.FirewallProtocolRules); err != nil {
				logger.Error(err, "Fail to load ingress firewall fail safe rules", "rule", rule)
				return err
			}
			logger.Info("Running rules loader", "ifaceName", ifaceName, "isDelete", isDelete)
			if err := e.c.IngressNodeFwRulesLoader(*rule, isDelete, ifID); err != nil {
				logger.Error(err, "Fail to load/unload ingress firewall rule", "rule", rule, "isDelete", isDelete)
				return err
			}
		}

		/*
			if ok && isDelete {
				logger.Info("Running detach operation", "ifaceName", ifaceName)
				_, err := e.c.IngressNodeFwAttach([]string{ifaceName}, isDelete)
				if err != nil {
					logger.Error(err, "Fail to detach ingress firewall prog")
					return err
				}
			}*/
	}

	if e.stats != nil {
		e.stats.StartPoll(e.c.GetStatisticsMap())
	}

	return nil
}

// addFailSaferules appends failSafe rules to user configured one
func addFailSaferules(rules *[]infv1alpha1.IngressNodeFirewallProtocolRule) error {
	if rules == nil {
		return fmt.Errorf("invalid rules")
	}
	fsRuleIndex := failsaferules.MAX_INGRESS_RULES
	// Add TCP failsafe rules
	tcpFailSafeRules := failsaferules.GetTCP()
	for _, rule := range tcpFailSafeRules {
		rule := rule
		fsRule := infv1alpha1.IngressNodeFirewallProtocolRule{}
		fsRule.ProtocolRule = new(infv1alpha1.IngressNodeFirewallProtoRule)
		fsRule.Order = uint32(fsRuleIndex)
		fsRuleIndex += 1
		fsRule.Protocol = infv1alpha1.ProtocolTypeTCP
		(*fsRule.ProtocolRule).Ports = strconv.Itoa(int(rule.GetPort()))
		fsRule.Action = infv1alpha1.IngressNodeFirewallAllow
		*rules = append(*rules, fsRule)
	}
	// Add UDP failsafe rules
	udpFailSafeRules := failsaferules.GetUDP()
	for _, rule := range udpFailSafeRules {
		rule := rule
		fsRule := infv1alpha1.IngressNodeFirewallProtocolRule{}
		fsRule.ProtocolRule = new(infv1alpha1.IngressNodeFirewallProtoRule)
		fsRule.Order = uint32(fsRuleIndex)
		fsRuleIndex += 1
		fsRule.Protocol = infv1alpha1.ProtocolTypeUDP
		(*fsRule.ProtocolRule).Ports = strconv.Itoa(int(rule.GetPort()))
		fsRule.Action = infv1alpha1.IngressNodeFirewallAllow
		*rules = append(*rules, fsRule)
	}
	return nil
}
