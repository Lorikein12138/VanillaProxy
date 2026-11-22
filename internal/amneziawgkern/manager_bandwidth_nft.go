package amneziawgkern

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/amneziawg"
)

const bandwidthNATMarker = "# vanillaproxy-amneziawg-nat-v1 "

type bandwidthNAT struct {
	Generation     string
	GateGeneration string `json:",omitempty"`
	IfIndex        int    `json:",omitempty"`
	Egress         string
	Subnets        []netip.Prefix
	Forward        bool
}

func newBandwidthNAT(s spec, forward bool) (bandwidthNAT, error) {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return bandwidthNAT{}, err
	}
	generation := hex.EncodeToString(token[:])
	nat := bandwidthNAT{Generation: generation, GateGeneration: generation, Egress: s.forward.egress, Forward: forward}
	for _, address := range s.addresses {
		nat.Subnets = append(nat.Subnets, netip.MustParsePrefix(address).Masked())
	}
	return nat, nil
}

func parseBandwidthNATLine(line string) (bandwidthNAT, bool) {
	var nat bandwidthNAT
	raw, ok := strings.CutPrefix(line, bandwidthNATMarker)
	if !ok || json.Unmarshal([]byte(raw), &nat) != nil {
		return nat, false
	}
	token, err := hex.DecodeString(nat.Generation)
	if err != nil || len(token) != 16 || hex.EncodeToString(token) != nat.Generation ||
		(nat.GateGeneration != "" && nat.GateGeneration != nat.Generation) ||
		nat.IfIndex < 0 || uint64(nat.IfIndex) > uint64(^uint32(0)) ||
		nat.Egress == "" || amneziawg.ValidateInterfaceName(nat.Egress) != nil || len(nat.Subnets) == 0 {
		return nat, false
	}
	for _, prefix := range nat.Subnets {
		if !prefix.Addr().Is4() || prefix != prefix.Masked() {
			return nat, false
		}
	}
	return nat, true
}

func bandwidthNATState(config string) (bandwidthNAT, bool) {
	lines := strings.SplitN(config, "\n", 4)
	if len(lines) < 4 {
		return bandwidthNAT{}, false
	}
	return parseBandwidthNATLine(lines[2])
}

func bandwidthNATTable(id int) string { return fmt.Sprintf("xui_awg_managed_nat_%d", id) }

func (nat bandwidthNAT) comment(name string) string {
	return "vanillaproxy-awg-nat-v1 " + name + " " + nat.Generation
}

func (nat bandwidthNAT) create(id int, name string) string {
	table := bandwidthNATTable(id)
	var script strings.Builder
	fmt.Fprintf(&script, "create table ip %s { comment %q; }\n", table, nat.comment(name))
	fmt.Fprintf(&script, "add chain ip %s postrouting { type nat hook postrouting priority 100; policy accept; }\n", table)
	for _, prefix := range nat.Subnets {
		fmt.Fprintf(&script, "add rule ip %s postrouting meta iif %d meta iifname %q ip saddr %s meta oifname %q masquerade\n",
			table, nat.IfIndex, name, prefix, nat.Egress)
	}
	return script.String()
}

func matchBandwidthNATRule(expr json.RawMessage, prefix netip.Prefix, ingress string, nat bandwidthNAT) bool {
	right := fmt.Sprintf("%q", prefix.Addr())
	if prefix.Bits() != 32 {
		right = fmt.Sprintf(`{"prefix":{"addr":%q,"len":%d}}`, prefix.Addr(), prefix.Bits())
	}
	// With the link gone, nft lists its index as a decimal string instead
	// of an interface name.
	const shape = `[{"match":{"op":"==","left":{"meta":{"key":"iif"}},"right":%q}},{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":%q}},{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":%s}},{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":%q}},{"masquerade":null}]`
	expected := fmt.Sprintf(shape, fmt.Sprint(nat.IfIndex), ingress, right, nat.Egress)
	var actualValue, expectedValue any
	return json.Unmarshal(expr, &actualValue) == nil && json.Unmarshal([]byte(expected), &expectedValue) == nil &&
		reflect.DeepEqual(actualValue, expectedValue)
}

// nftables 1.0.6 omits the table comment in JSON. Read its canonical text
// header and table-level comment only after JSON identifies the same handle.
func nftTableComment(raw json.RawMessage, comment, family, name string, handle uint64, command func(string, string, ...string) (string, error)) (string, bool) {
	if exactNftFields(raw, "family", "name", "handle", "comment") {
		return comment, true
	}
	if !exactNftFields(raw, "family", "name", "handle") || handle == 0 || command == nil {
		return "", false
	}
	output, err := command("", "nft", "-an", "list", "table", family, name)
	if err != nil {
		return "", false
	}
	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
	header := fmt.Sprintf("table %s %s { # handle %d", family, name, handle)
	if len(lines) < 3 || lines[0] != header || lines[len(lines)-1] != "}" {
		return "", false
	}
	quoted, ok := strings.CutPrefix(lines[1], "\tcomment ")
	if !ok {
		return "", false
	}
	comment, err = strconv.Unquote(quoted)
	if err != nil || strconv.Quote(comment) != quoted {
		return "", false
	}
	for _, line := range lines[2 : len(lines)-1] {
		if line != "" && (!strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "\tcomment ")) {
			return "", false
		}
	}
	return comment, true
}

func exactNftFields(data json.RawMessage, fields ...string) bool {
	var object map[string]json.RawMessage
	if json.Unmarshal(data, &object) != nil || len(object) != len(fields) {
		return false
	}
	for _, field := range fields {
		if _, exists := object[field]; !exists {
			return false
		}
	}
	return true
}

func ownedBandwidthNATHandle(raw string, id int, name string, nat bandwidthNAT, command func(string, string, ...string) (string, error)) (uint64, error) {
	var listing struct {
		Nftables []map[string]json.RawMessage
	}
	if err := json.Unmarshal([]byte(raw), &listing); err != nil || listing.Nftables == nil {
		return 0, fmt.Errorf("amneziawgkern: invalid nftables NAT listing")
	}
	table := bandwidthNATTable(id)
	conflict := fmt.Errorf("amneziawgkern: refusing to remove changed or foreign NAT table %s", table)
	var handle uint64
	chains, rules := 0, 0
	for _, item := range listing.Nftables {
		for kind, object := range item {
			var header struct {
				Family, Table, Name, Comment, Type, Hook, Policy, Chain string
				Handle                                                  uint64
				Prio                                                    int
				Expr                                                    json.RawMessage
			}
			if json.Unmarshal(object, &header) != nil {
				return 0, conflict
			}
			if header.Family != "ip" || (header.Table != table && !(kind == "table" && header.Name == table)) {
				continue
			}
			var fields map[string]json.RawMessage
			if len(item) != 1 || header.Handle == 0 || json.Unmarshal(object, &fields) != nil {
				return 0, conflict
			}
			switch kind {
			case "table":
				comment, ok := nftTableComment(object, header.Comment, "ip", table, header.Handle, command)
				if handle != 0 || !ok || comment != nat.comment(name) {
					return 0, conflict
				}
				handle = header.Handle
			case "chain":
				chains++
				if header.Name != "postrouting" || header.Type != "nat" || header.Hook != "postrouting" ||
					header.Policy != "accept" || header.Prio != 100 || len(fields) != 8 {
					return 0, conflict
				}
			case "rule":
				if rules >= len(nat.Subnets) || header.Chain != "postrouting" || len(fields) != 5 || nat.IfIndex == 0 ||
					!matchBandwidthNATRule(header.Expr, nat.Subnets[rules], name, nat) {
					return 0, conflict
				}
				rules++
			default:
				return 0, conflict
			}
		}
	}
	if handle == 0 && chains == 0 && rules == 0 {
		return 0, nil
	}
	if handle == 0 || chains != 1 || rules != len(nat.Subnets) {
		return 0, conflict
	}
	return handle, nil
}

func (m *Manager) applyBandwidthEgress(id int, name string, nat bandwidthNAT) error {
	iface, err := m.bandwidth.lookup(name)
	if err != nil {
		return fmt.Errorf("amneziawgkern: inspect managed NAT ingress %s: %w", name, err)
	}
	if iface.Index <= 0 || iface.Flags&net.FlagUp != 0 || iface.Index != m.ifaces[id].bandwidthIndex {
		return fmt.Errorf("amneziawgkern: managed NAT ingress %s is no longer the owned down interface", name)
	}
	// Persist the exact index before creating rules. An interrupted setup
	// can then distinguish an uncreated table from a recovered generation.
	config, found, err := readOwnedConfig(m.confDir, id)
	if err != nil {
		return err
	}
	stored, ok := bandwidthNATState(config)
	if !found || !isBandwidthOwnedConfig(config, name) || !ok || !reflect.DeepEqual(stored, nat) {
		return fmt.Errorf("amneziawgkern: managed NAT configuration for %s changed during setup", name)
	}
	nat.IfIndex = iface.Index
	natConfig, err := json.Marshal(nat)
	if err != nil {
		return err
	}
	lines := strings.SplitN(config, "\n", 4)
	lines[2] = bandwidthNATMarker + string(natConfig)
	if err := writeConf(m.confDir, name, strings.Join(lines, "\n")); err != nil {
		return err
	}
	if out, err := m.host.run(nat.create(id, name), "nft", "-f", "-"); err != nil {
		return fmt.Errorf("amneziawgkern: create managed NAT for %s: %w (%s)", name, err, out)
	}
	if err := m.host.enableIPv4Forwarding(); err != nil {
		return fmt.Errorf("amneziawgkern: enabling IPv4 forwarding: %w", err)
	}
	if nat.Forward {
		for _, rule := range nat.forwardRules(name) {
			args := append([]string{"-w", "5", "-I", "FORWARD", "1"}, rule...)
			if out, err := m.host.run("", "iptables", args...); err != nil {
				return fmt.Errorf("amneziawgkern: create managed FORWARD rule for %s: %w (%s)", name, err, out)
			}
		}
	}
	return nil
}

func (nat bandwidthNAT) forwardRules(name string) [][]string {
	rules := (forwardRules{tunnel: name, egress: nat.Egress}).rules()
	for _, rule := range rules {
		rule[slices.Index(rule, "--comment")+1] = "vanillaproxy-awg-" + nat.Generation
	}
	return rules
}

func (m *Manager) removeBandwidthEgress(id int, name string, nat bandwidthNAT) error {
	if nat.IfIndex == 0 {
		// The setup did not reach rule installation. A same-name table
		// has no association with this stored generation.
		return nil
	}
	listing, err := m.host.run("", "nft", "-ajn", "list", "ruleset")
	if err != nil {
		return fmt.Errorf("amneziawgkern: inspect managed NAT for %s: %w (%s)", name, err, listing)
	}
	handle, err := ownedBandwidthNATHandle(listing, id, name, nat, m.host.run)
	if err != nil {
		return err
	}
	if handle != 0 {
		if out, err := m.host.run(fmt.Sprintf("delete table ip handle %d\n", handle), "nft", "-f", "-"); err != nil {
			return fmt.Errorf("amneziawgkern: remove managed NAT for %s: %w (%s)", name, err, out)
		}
	}
	if !nat.Forward {
		return nil
	}
	listing, err = m.host.run("", "iptables", "-w", "5", "-S", "FORWARD")
	if err != nil {
		return fmt.Errorf("amneziawgkern: inspect managed FORWARD rules: %w (%s)", err, listing)
	}
	for _, rule := range nat.forwardRules(name) {
		expected := append([]string{"-A", "FORWARD"}, rule...)
		for _, line := range strings.Split(listing, "\n") {
			words := strings.Fields(line)
			for j, word := range words {
				words[j] = strings.Trim(word, `"`)
			}
			if slices.Equal(words, expected) {
				args := append([]string{"-w", "5", "-D", "FORWARD"}, rule...)
				if out, err := m.host.run("", "iptables", args...); err != nil {
					return fmt.Errorf("amneziawgkern: remove managed FORWARD rule for %s: %w (%s)", name, err, out)
				}
				break
			}
		}
	}
	return nil
}
