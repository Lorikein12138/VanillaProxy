package service

import (
	"errors"
	"fmt"
	"slices"

	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthexchange"
	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthruntime"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/mtproto"
)

func (node *managedBandwidthNode) mtprotoOptions(inst mtproto.Instance) (*mtproto.BandwidthOptions, error) {
	if node.closing.Load() {
		return nil, errors.New("bandwidth node is shutting down")
	}
	if inst.RouteThroughXray {
		return nil, errors.New("bandwidth node requires direct MTProto egress")
	}
	options := &mtproto.BandwidthOptions{
		IPC:       node.panel.Node().IPCInfo(),
		ClientIDs: make(map[string]string, len(inst.Secrets)),
	}
	lookup := node.panel.AutomaticAccountLookup()
	if lookup == nil {
		for _, secret := range inst.Secrets {
			id, ok := node.panel.AccountID(secret.Name)
			if !ok {
				return nil, fmt.Errorf("MTProto inbound %q has a client without a canonical bandwidth account", inst.Tag)
			}
			options.ClientIDs[secret.Name] = id
		}
		return options, nil
	}

	const protocol = string(model.MTProto)
	options.PolicyBindings = make(map[string]string, len(inst.Secrets))
	for _, secret := range inst.Secrets {
		credential := mtproto.BandwidthCredential(secret.Secret)
		if id, allowed := lookup(protocol, secret.Name, credential); allowed && credential != "" {
			options.ClientIDs[secret.Name] = id
			options.PolicyBindings[secret.Name] = bandwidthexchange.CredentialFingerprint(protocol, credential)
		}
	}
	return options, nil
}

func (s *XrayService) reconcileBandwidthMTProtoPolicy(node *managedBandwidthNode) error {
	if node.panel.AutomaticAccountLookup() == nil {
		return nil
	}
	manager := mtproto.GetManager()
	desired, err := s.inboundService.DesiredMtprotoInstances()
	if err != nil {
		return errors.Join(err, manager.Reconcile(nil))
	}
	desired = slices.DeleteFunc(desired, func(inst mtproto.Instance) bool { return inst.RouteThroughXray })
	return manager.Reconcile(desired)
}

func addLiveBandwidthMTProtoAccounts(accounts bandwidthruntime.XrayPolicyLiveAccounts) {
	for email, bindings := range mtproto.GetManager().ReadyBandwidthBindings() {
		for _, binding := range bindings {
			accounts.Add(email, binding)
		}
	}
}
