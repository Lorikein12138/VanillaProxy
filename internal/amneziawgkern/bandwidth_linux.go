//go:build linux

package amneziawgkern

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"golang.org/x/sys/unix"
)

// Queue messages and attributes use Linux's UAPI nfnetlink_queue.h.
const (
	bwQueuePacket  = unix.NFNL_SUBSYS_QUEUE<<8 | 0
	bwQueueVerdict = unix.NFNL_SUBSYS_QUEUE<<8 | 1
	bwQueueConfig  = unix.NFNL_SUBSYS_QUEUE<<8 | 2

	bwAttrPacket  = 1
	bwAttrVerdict = 2
	bwAttrIn      = 5
	bwAttrOut     = 6
	bwAttrPayload = 10
	bwAttrLength  = 13
	bwAttrSKB     = 14

	bwConfigCommand = 1
	bwConfigParams  = 2
	bwConfigMax     = 3
	bwConfigMask    = 4
	bwConfigFlags   = 5

	bwCopyPacket        = 2
	bwBindQueue         = 1
	bwFailOpen          = 1 << 0
	bwDeliverGSO        = 1 << 2
	bwPacketGSO         = 1 << 1
	bwHeaderBytes       = 60
	bwPendingMax        = 1024
	bwPendingPerAccount = 32
	bwQueueMax          = 2 * bwPendingMax
	bwPriority          = -450
	bwMarker            = "vanillaproxy-awg-bandwidth-v1"
	bwDrop              = 0
	bwAccept            = 1
)

type bandwidthPacket struct {
	id        uint32
	bytes     int
	account   string
	unmetered bool
	deadline  time.Time
}

type bandwidthAccountQueue struct {
	packets chan bandwidthPacket
	pending int
}

// BandwidthGate owns one queue and one nftables table in the current namespace.
// Block must precede link deletion. Close releases resources after deletion.
type BandwidthGate struct {
	fd        int
	monitorFD int
	queue     uint16
	name      string
	ifIndex   int
	table     string
	comment   string
	closeMu   sync.Mutex
	closed    bool

	ctx         context.Context
	cancel      context.CancelFunc
	wait        func(context.Context, string, int) error
	routes      []BandwidthRoute
	done        chan struct{}
	monitorDone chan struct{}
	workers     sync.WaitGroup
	mu          sync.Mutex
	stopping    bool
	failed      bool
	paused      bool
	pending     int
	perAccount  map[string]*bandwidthAccountQueue
}

func validateBandwidthRoutes(routes []BandwidthRoute) ([]BandwidthRoute, error) {
	result := make([]BandwidthRoute, 0, len(routes))
	for _, route := range routes {
		if !route.AllowedIP.IsValid() || !route.AllowedIP.Addr().Is4() || route.Unmetered != (route.AccountID == "") || strings.TrimSpace(route.AccountID) != route.AccountID {
			return nil, errors.New("amneziawgkern: invalid bandwidth peer binding")
		}
		route.AllowedIP = route.AllowedIP.Masked()
		for _, existing := range result {
			if existing.AllowedIP.Overlaps(route.AllowedIP) {
				return nil, errors.New("amneziawgkern: bandwidth peer bindings overlap")
			}
		}
		result = append(result, route)
	}
	return result, nil
}

func OpenBandwidthGate(ifName string, ifIndex int, routes []BandwidthRoute, wait func(context.Context, string, int) error) (*BandwidthGate, error) {
	var generation [16]byte
	if _, err := rand.Read(generation[:]); err != nil {
		return nil, err
	}
	return openBandwidthGate(ifName, ifIndex, hex.EncodeToString(generation[:]), routes, wait)
}

func openBandwidthGate(ifName string, ifIndex int, generation string, routes []BandwidthRoute, wait func(context.Context, string, int) error) (*BandwidthGate, error) {
	id, ok := parseOwnedInterfaceName(ifName)
	token, tokenErr := hex.DecodeString(generation)
	if !ok || ifIndex <= 0 || uint64(ifIndex) > uint64(^uint32(0)) || wait == nil || tokenErr != nil || len(token) != 16 || hex.EncodeToString(token) != generation {
		return nil, errors.New("amneziawgkern: invalid bandwidth interface or permit callback")
	}
	bindings, err := validateBandwidthRoutes(routes)
	if err != nil {
		return nil, err
	}
	iface, err := net.InterfaceByName(ifName)
	if err != nil || iface.Index != ifIndex || iface.Flags&net.FlagUp != 0 {
		return nil, errors.New("amneziawgkern: bandwidth gate requires its owned interface to be down")
	}
	monitorFD, err := openBandwidthRuleMonitor()
	if err != nil {
		return nil, err
	}
	keepMonitor := false
	defer func() {
		if !keepMonitor {
			_ = unix.Close(monitorFD)
		}
	}()
	rules, err := readBandwidthRules()
	if err != nil {
		return nil, err
	}
	table := bandwidthTableName(id)
	if err := validateBandwidthNamespace(rules, table, ifName, ""); err != nil {
		return nil, err
	}
	fd, queue, err := openBandwidthQueue(binary.BigEndian.Uint16(token[:2]), bandwidthReservedQueues(rules))
	if err != nil {
		return nil, err
	}
	comment := fmt.Sprintf("%s %s %d %d %s", bwMarker, ifName, ifIndex, queue, generation)
	if err := nftBandwidthWrite(bandwidthRules(table, ifName, ifIndex, queue, comment)); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	// Catch setup events accumulated during the atomic nft transaction.
	_, err = collectBandwidthRuleEvents(monitorFD, make([]byte, 65536))
	if err == nil {
		rules, err = readBandwidthRules()
		if err == nil {
			err = validateBandwidthNamespace(rules, table, ifName, comment)
		}
	}
	if err != nil {
		// The manager still owns a down link and will retry cleanup after
		// deleting it. Keep any verified owned table fail-closed.
		_ = unix.Close(fd)
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	gate := &BandwidthGate{
		fd: fd, monitorFD: monitorFD, queue: queue, name: ifName, ifIndex: ifIndex, table: table, comment: comment,
		ctx: ctx, cancel: cancel, wait: wait, routes: bindings, done: make(chan struct{}),
		monitorDone: make(chan struct{}),
		perAccount:  make(map[string]*bandwidthAccountQueue),
	}
	keepMonitor = true
	go gate.serve()
	go gate.monitorRules()
	return gate, nil
}

func (g *BandwidthGate) Healthy() bool {
	return g.ctx.Err() == nil
}

// Block cannot race an accept verdict. The owned queue socket remains reserved
// through link deletion, and no new accepted verdict is sent.
func (g *BandwidthGate) Block() {
	g.mu.Lock()
	g.stopping = true
	g.cancel()
	g.mu.Unlock()
	<-g.done
	<-g.monitorDone
}

func (g *BandwidthGate) Close() error {
	g.Block()
	g.closeMu.Lock()
	defer g.closeMu.Unlock()
	if g.closed {
		return nil
	}
	if err := removeBandwidthTable(g.name, g.comment, ""); err != nil {
		return err
	}
	g.closed = true
	return unix.Close(g.fd)
}

// RemoveStaleBandwidthGate is for recovery after the manager has confirmed
// ownership of and removed the old interface. It never changes existing links.
func RemoveStaleBandwidthGate(ifName string) error {
	return removeStaleBandwidthGate(ifName, "")
}

func removeStaleBandwidthGate(ifName, generation string) error {
	return removeBandwidthTable(ifName, "", generation)
}

func bandwidthTableName(id int) string {
	return fmt.Sprintf("xui_awg_bw_%d", id)
}

func bandwidthRules(table, ifName string, ifIndex int, queue uint16, comment string) string {
	return fmt.Sprintf(
		"create table inet %[1]s { comment %[5]q; }\n"+
			"add chain inet %[1]s upload { type filter hook prerouting priority %[6]d; policy accept; }\n"+
			"add chain inet %[1]s download { type filter hook postrouting priority %[6]d; policy accept; }\n"+
			"add rule inet %[1]s upload meta iif %[3]d meta iifname %[2]q queue num %[4]d\n"+
			"add rule inet %[1]s download meta oif %[3]d meta oifname %[2]q queue num %[4]d\n",
		table, ifName, ifIndex, queue, comment, bwPriority,
	)
}

type bandwidthNftItem struct {
	Flowtable json.RawMessage `json:"flowtable"`
	objects   map[string]json.RawMessage
	Table     struct {
		Family  string
		Name    string
		Handle  uint64
		Comment string
	}
	Chain struct {
		Family string
		Table  string
		Name   string
		Type   string
		Hook   string
		Prio   int
		Policy string
	}
	Rule struct {
		Family string
		Table  string
		Chain  string
		Expr   []map[string]json.RawMessage
	}
}

func (item *bandwidthNftItem) UnmarshalJSON(data []byte) error {
	type nftObject bandwidthNftItem
	if err := json.Unmarshal(data, (*nftObject)(item)); err != nil {
		return err
	}
	return json.Unmarshal(data, &item.objects)
}

func equivalentNftJSON(actual json.RawMessage, expected string) bool {
	var actualValue, expectedValue any
	return json.Unmarshal(actual, &actualValue) == nil && json.Unmarshal([]byte(expected), &expectedValue) == nil &&
		reflect.DeepEqual(actualValue, expectedValue)
}

func validateBandwidthNamespace(items []bandwidthNftItem, table, ifName, comment string) error {
	handle, err := ownedBandwidthTable(items, table, ifName, comment, "", comment != "")
	if err != nil {
		return err
	}
	if comment == "" && handle != 0 {
		return fmt.Errorf("amneziawgkern: bandwidth table %s already exists", table)
	}
	if comment != "" && handle == 0 {
		return fmt.Errorf("amneziawgkern: required bandwidth table %s is missing", table)
	}
	owned := map[string]bool{table: handle != 0}
	for _, item := range items {
		if len(item.Flowtable) > 0 {
			return errors.New("amneziawgkern: nftables flowtables can bypass an interface bandwidth gate")
		}
		for _, expr := range item.Rule.Expr {
			queue := len(expr["queue"]) > 0
			compat := strings.Contains(strings.ToUpper(string(expr["xt"])), "NFQUEUE")
			if !queue && !compat {
				continue
			}
			if item.Rule.Family != "inet" {
				return errors.New("amneziawgkern: external nftables NFQUEUE rules require an isolated namespace")
			}
			ruleTable := item.Rule.Table
			if !owned[ruleTable] {
				otherID, err := strconv.Atoi(strings.TrimPrefix(ruleTable, "xui_awg_bw_"))
				if err != nil || otherID <= 0 || bandwidthTableName(otherID) != ruleTable {
					return errors.New("amneziawgkern: external nftables NFQUEUE rules require an isolated namespace")
				}
				if h, err := ownedBandwidthTable(items, ruleTable, ownedInterfaceName(otherID), "", "", true); err != nil || h == 0 {
					return errors.New("amneziawgkern: external nftables NFQUEUE rules require an isolated namespace")
				}
				owned[ruleTable] = true
			}
		}
	}
	return nil
}

func bandwidthReservedQueues(items []bandwidthNftItem) map[uint16]bool {
	reserved := make(map[uint16]bool)
	for _, item := range items {
		for _, expr := range item.Rule.Expr {
			var queue struct{ Num uint16 }
			if len(expr["queue"]) > 0 && json.Unmarshal(expr["queue"], &queue) == nil {
				reserved[queue.Num] = true
			}
		}
	}
	return reserved
}

func readBandwidthRules() ([]bandwidthNftItem, error) {
	out, err := run("", "nft", "-ajn", "list", "ruleset")
	if err != nil {
		return nil, fmt.Errorf("amneziawgkern: inspect nftables bandwidth rules: %w: %s", err, out)
	}
	var state struct{ Nftables []bandwidthNftItem }
	if err := json.Unmarshal([]byte(out), &state); err != nil {
		return nil, fmt.Errorf("amneziawgkern: invalid nftables listing: %w", err)
	}
	return state.Nftables, nil
}

func nftBandwidthWrite(transaction string) error {
	if out, err := run(transaction, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("amneziawgkern: set nftables bandwidth rules: %w: %s", err, out)
	}
	return nil
}

func removeBandwidthTable(ifName, comment, generation string) error {
	id, ok := parseOwnedInterfaceName(ifName)
	if !ok {
		return errors.New("amneziawgkern: invalid bandwidth interface")
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, iface := range ifaces {
		if iface.Name == ifName {
			return errors.New("amneziawgkern: cannot remove bandwidth rules for an existing interface")
		}
	}
	items, err := readBandwidthRules()
	if err != nil {
		return err
	}
	handle, err := ownedBandwidthTable(items, bandwidthTableName(id), ifName, comment, generation, false)
	if err != nil || handle == 0 {
		return err
	}
	// A handle also prevents deleting a same-name replacement between list and delete.
	return nftBandwidthWrite(fmt.Sprintf("delete table inet handle %d\n", handle))
}

func ownedBandwidthTable(items []bandwidthNftItem, table, ifName, comment, generation string, complete bool) (uint64, error) {
	bad := fmt.Errorf("amneziawgkern: refusing unowned bandwidth table %s", table)
	var handle uint64
	var index, queue string
	for _, item := range items {
		t := item.Table
		if t.Family != "inet" || t.Name != table {
			continue
		}
		marker, ok := nftTableComment(item.objects["table"], t.Comment, "inet", table, t.Handle, run)
		fields := strings.Fields(marker)
		if handle != 0 || t.Handle == 0 || !ok || len(fields) != 5 || fields[0] != bwMarker ||
			fields[1] != ifName || strings.Join(fields, " ") != marker || (comment != "" && marker != comment) || (generation != "" && fields[4] != generation) {
			return 0, bad
		}
		decoded, err := hex.DecodeString(fields[4])
		indexNumber, indexErr := strconv.ParseUint(fields[2], 10, 32)
		queueNumber, queueErr := strconv.ParseUint(fields[3], 10, 16)
		if err != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != fields[4] || indexErr != nil || indexNumber == 0 || queueErr != nil || queueNumber < 0x8000 ||
			strconv.FormatUint(indexNumber, 10) != fields[2] || strconv.FormatUint(queueNumber, 10) != fields[3] {
			return 0, bad
		}
		handle, index, queue = t.Handle, fields[2], fields[3]
	}
	if handle == 0 {
		return 0, nil
	}
	// nft JSON may resolve the numeric meta iif/oif to a live name,
	// even in numeric output mode. Only accept the kernel name at this index.
	var indexName string
	if number, err := strconv.Atoi(index); err == nil {
		if iface, err := net.InterfaceByIndex(number); err == nil {
			indexName = iface.Name
		}
	}
	seenChains := make(map[string]bool, 2)
	seenRules := make(map[string]bool, 2)
	for _, item := range items {
		for kind, data := range item.objects {
			if kind == "table" || kind == "chain" || kind == "rule" {
				continue
			}
			var location struct{ Family, Table string }
			if json.Unmarshal(data, &location) == nil && location.Family == "inet" && location.Table == table {
				return 0, bad
			}
		}
		c, r := item.Chain, item.Rule
		if c.Family == "inet" && c.Table == table {
			hook := map[string]string{"upload": "prerouting", "download": "postrouting"}[c.Name]
			if hook == "" || seenChains[c.Name] || c.Type != "filter" || c.Hook != hook || c.Prio != bwPriority || c.Policy != "accept" ||
				!exactNftFields(item.objects["chain"], "family", "table", "name", "handle", "type", "hook", "prio", "policy") {
				return 0, bad
			}
			seenChains[c.Name] = true
		}
		if r.Family == "inet" && r.Table == table {
			field := map[string]string{"upload": "iif", "download": "oif"}[r.Chain]
			if field == "" || seenRules[r.Chain] || len(r.Expr) != 3 ||
				!exactNftFields(item.objects["rule"], "family", "table", "chain", "handle", "expr") {
				return 0, bad
			}
			match := func(key, value string) string {
				return fmt.Sprintf(`{"op":"==","left":{"meta":{"key":%q}},"right":%q}`, key, value)
			}
			indexMatch := equivalentNftJSON(r.Expr[0]["match"], match(field, index)) ||
				(indexName != "" && equivalentNftJSON(r.Expr[0]["match"], match(field, indexName)))
			if len(r.Expr[0]) != 1 || !indexMatch ||
				len(r.Expr[1]) != 1 || !equivalentNftJSON(r.Expr[1]["match"], match(field+"name", ifName)) ||
				len(r.Expr[2]) != 1 || !equivalentNftJSON(r.Expr[2]["queue"], `{"num":`+queue+`}`) {
				return 0, bad
			}
			seenRules[r.Chain] = true
		}
	}
	if complete && (len(seenChains) != 2 || len(seenRules) != 2) {
		return 0, bad
	}
	return handle, nil
}

func openBandwidthRuleMonitor() (int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_NETFILTER)
	if err != nil {
		return -1, fmt.Errorf("amneziawgkern: open bandwidth rule monitor: %w", err)
	}
	if err = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err == nil {
		err = unix.SetsockoptInt(fd, unix.SOL_NETLINK, unix.NETLINK_ADD_MEMBERSHIP, unix.NFNLGRP_NFTABLES)
	}
	if err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("amneziawgkern: subscribe to bandwidth rule changes: %w", err)
	}
	return fd, nil
}

func collectBandwidthRuleEvents(fd int, buf []byte) (bool, error) {
	changed := false
	for range 256 {
		n, _, flags, from, err := unix.Recvmsg(fd, buf, nil, unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EAGAIN) {
			return changed, nil
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return false, err
		}
		source, ok := from.(*unix.SockaddrNetlink)
		if !ok || source.Pid != 0 {
			continue
		}
		if flags&unix.MSG_TRUNC != 0 {
			return false, errors.New("truncated nftables notification")
		}
		messages, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return false, err
		}
		for _, message := range messages {
			switch message.Header.Type {
			case unix.NLMSG_OVERRUN, unix.NLMSG_ERROR:
				return false, errors.New("lost nftables notifications")
			default:
				changed = changed || message.Header.Type>>8 == unix.NFNL_SUBSYS_NFTABLES
			}
		}
	}
	return changed, nil // Remaining notifications keep the socket readable.
}

func (g *BandwidthGate) monitorRules() {
	defer close(g.monitorDone)
	defer unix.Close(g.monitorFD)
	buf := make([]byte, 65536)
	fds := []unix.PollFd{{Fd: int32(g.monitorFD), Events: unix.POLLIN}}
	for g.ctx.Err() == nil {
		ready, err := unix.Poll(fds, 100)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || fds[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			g.stopUnexpected("nftables monitor unavailable", err)
			return
		}
		if ready == 0 {
			continue
		}
		g.mu.Lock()
		g.paused = true
		g.mu.Unlock()
		changed, err := collectBandwidthRuleEvents(g.monitorFD, buf)
		if err == nil && changed {
			var rules []bandwidthNftItem
			rules, err = readBandwidthRules()
			if err == nil {
				err = validateBandwidthNamespace(rules, g.table, g.name, g.comment)
			}
		}
		if err != nil {
			g.stopUnexpected("nftables bandwidth path changed", err)
			return
		}
		g.mu.Lock()
		g.paused = false
		g.mu.Unlock()
	}
}

func (g *BandwidthGate) stopUnexpected(reason string, err error) {
	g.mu.Lock()
	disable := !g.stopping && !g.failed
	g.failed = true
	g.cancel()
	g.mu.Unlock()
	if !disable {
		return
	}
	logger.Warning("amneziawgkern: disabling ", g.name, ": ", reason, " ", err)
	if err := downBandwidthLink(g.name, g.ifIndex); err != nil {
		logger.Warning("amneziawgkern: could not disable ", g.name, ": ", err)
	}
}

func downBandwidthLink(ifName string, ifIndex int) error {
	iface, err := net.InterfaceByIndex(ifIndex)
	if err != nil {
		// A concurrently removed link cannot pass traffic. Do not fall back
		// to looking up its name, since that might select a replacement.
		return err
	}
	if iface.Name != ifName || iface.Flags&net.FlagUp == 0 {
		return nil
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	message := make([]byte, unix.NLMSG_HDRLEN+unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(message[0:4], uint32(len(message)))
	binary.NativeEndian.PutUint16(message[4:6], unix.RTM_NEWLINK)
	binary.NativeEndian.PutUint16(message[6:8], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	binary.NativeEndian.PutUint32(message[8:12], 1)
	binary.NativeEndian.PutUint32(message[20:24], uint32(ifIndex))
	binary.NativeEndian.PutUint32(message[28:32], unix.IFF_UP)
	if err := sendBandwidthMessage(fd, message); err != nil {
		return err
	}
	return bandwidthNetlinkAck(fd, 1)
}

func openBandwidthQueue(seed uint16, reserved map[uint16]bool) (int, uint16, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_NETFILTER)
	if err != nil {
		return -1, 0, fmt.Errorf("amneziawgkern: open bandwidth queue: %w", err)
	}
	keep := false
	defer func() {
		if !keep {
			_ = unix.Close(fd)
		}
	}()
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return -1, 0, fmt.Errorf("amneziawgkern: bind bandwidth socket: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 2<<20); err != nil {
		return -1, 0, err
	}
	config := appendBandwidthAttr(nil, bwConfigCommand, []byte{bwBindQueue, 0, 0, 0})
	config = appendBandwidthAttr(config, bwConfigParams, []byte{0, 0, 0, bwHeaderBytes, bwCopyPacket})
	config = appendBandwidthAttr(config, bwConfigMax, binary.BigEndian.AppendUint32(nil, bwQueueMax))
	config = appendBandwidthAttr(config, bwConfigMask, binary.BigEndian.AppendUint32(nil, bwFailOpen|bwDeliverGSO))
	config = appendBandwidthAttr(config, bwConfigFlags, binary.BigEndian.AppendUint32(nil, 0))
	err = errors.New("no unreserved NFQUEUE ID found")
	for attempt := range 64 {
		queue := uint16(0x8000) | ((seed + uint16(attempt)) & 0x7fff)
		if reserved[queue] {
			continue
		}
		if err = configureBandwidthQueue(fd, queue, uint32(attempt+1), config); err == nil {
			keep = true
			return fd, queue, nil
		}
		if !errors.Is(err, unix.EPERM) && !errors.Is(err, unix.EBUSY) {
			break
		}
	}
	return -1, 0, fmt.Errorf("amneziawgkern: configure exclusive bandwidth queue: %w", err)
}

func configureBandwidthQueue(fd int, queue uint16, seq uint32, attrs []byte) error {
	message := bandwidthMessage(bwQueueConfig, unix.NLM_F_REQUEST|unix.NLM_F_ACK, seq, queue, attrs)
	if err := sendBandwidthMessage(fd, message); err != nil {
		return err
	}
	return bandwidthNetlinkAck(fd, seq)
}

func bandwidthNetlinkAck(fd int, seq uint32) error {
	ready, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, 1500)
	if err != nil {
		return err
	}
	if ready == 0 {
		return errors.New("timed out waiting for kernel netlink acknowledgement")
	}
	messages, err := receiveBandwidthMessages(fd, make([]byte, 4096))
	if err != nil {
		return err
	}
	for _, message := range messages {
		if message.Header.Seq == seq && message.Header.Type == unix.NLMSG_ERROR && len(message.Data) >= 4 {
			code := int32(binary.NativeEndian.Uint32(message.Data))
			if code == 0 {
				return nil
			}
			if code < 0 {
				return unix.Errno(-code)
			}
		}
	}
	return errors.New("invalid kernel netlink acknowledgement")
}

func bandwidthMessage(kind, flags uint16, seq uint32, queue uint16, attrs []byte) []byte {
	const size = unix.NLMSG_HDRLEN + 4
	b := make([]byte, size, size+len(attrs))
	binary.NativeEndian.PutUint32(b[0:4], uint32(size+len(attrs)))
	binary.NativeEndian.PutUint16(b[4:6], kind)
	binary.NativeEndian.PutUint16(b[6:8], flags)
	binary.NativeEndian.PutUint32(b[8:12], seq)
	binary.BigEndian.PutUint16(b[18:20], queue)
	return append(b, attrs...)
}

func appendBandwidthAttr(dst []byte, kind uint16, value []byte) []byte {
	size := 4 + len(value)
	dst = binary.NativeEndian.AppendUint16(dst, uint16(size))
	dst = binary.NativeEndian.AppendUint16(dst, kind)
	dst = append(dst, value...)
	return append(dst, make([]byte, (4-size%4)%4)...)
}

func sendBandwidthMessage(fd int, message []byte) error {
	for {
		err := unix.Sendto(fd, message, unix.MSG_DONTWAIT, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

func receiveBandwidthMessages(fd int, buf []byte) ([]syscall.NetlinkMessage, error) {
	n, _, flags, from, err := unix.Recvmsg(fd, buf, nil, unix.MSG_DONTWAIT)
	if err != nil {
		return nil, err
	}
	source, ok := from.(*unix.SockaddrNetlink)
	if !ok || source.Pid != 0 || source.Groups != 0 {
		return nil, nil
	}
	if flags&unix.MSG_TRUNC != 0 {
		return nil, errors.New("truncated kernel NFQUEUE message")
	}
	return syscall.ParseNetlinkMessage(buf[:n])
}

func (g *BandwidthGate) serve() {
	defer close(g.done)
	defer g.workers.Wait()
	defer g.stopUnexpected("bandwidth queue stopped", nil)
	buf := make([]byte, 8192)
	fds := []unix.PollFd{{Fd: int32(g.fd), Events: unix.POLLIN}}
	for g.ctx.Err() == nil {
		ready, err := unix.Poll(fds, 100)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || fds[0].Revents&(unix.POLLHUP|unix.POLLNVAL) != 0 {
			return
		}
		if ready == 0 {
			continue
		}
		messages, err := receiveBandwidthMessages(g.fd, buf)
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.ENOBUFS) {
			continue
		}
		if err != nil {
			return
		}
		for _, message := range messages {
			if message.Header.Type != bwQueuePacket {
				continue
			}
			packet, known := g.parseBandwidthPacket(message.Data)
			if !known {
				return // No reliable ID to drop. Stop all verdicts until recovery.
			}
			g.enqueue(packet)
		}
	}
}

func (g *BandwidthGate) enqueue(packet bandwidthPacket) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ctx.Err() != nil {
		return
	}
	if packet.unmetered {
		g.verdict(packet.id, true)
		return
	}
	accountQueue := g.perAccount[packet.account]
	if packet.account == "" || g.pending >= bwPendingMax || (accountQueue != nil && accountQueue.pending >= bwPendingPerAccount) {
		g.verdict(packet.id, false)
		return
	}
	if accountQueue == nil {
		accountQueue = &bandwidthAccountQueue{packets: make(chan bandwidthPacket, bwPendingPerAccount)}
		g.perAccount[packet.account] = accountQueue
		g.workers.Add(1)
		go g.permitAccount(packet.account, accountQueue)
	}
	g.pending++
	accountQueue.pending++
	packet.deadline = time.Now().Add(6 * time.Second)
	accountQueue.packets <- packet
}

func (g *BandwidthGate) permitAccount(account string, queue *bandwidthAccountQueue) {
	defer g.workers.Done()
	for {
		packet := <-queue.packets
		ctx, cancel := context.WithDeadline(g.ctx, packet.deadline)
		allowed := ctx.Err() == nil && g.wait(ctx, account, packet.bytes) == nil
		allowed = allowed && ctx.Err() == nil
		cancel()
		g.mu.Lock()
		if g.ctx.Err() == nil {
			g.verdict(packet.id, allowed)
		}
		queue.pending--
		g.pending--
		if queue.pending == 0 {
			delete(g.perAccount, account)
			g.mu.Unlock()
			return
		}
		g.mu.Unlock()
	}
}

// verdict runs under mu so Block and accept cannot overlap.
func (g *BandwidthGate) verdict(id uint32, accepted bool) {
	value := uint32(bwDrop)
	if accepted && !g.paused {
		value = bwAccept
	}
	data := binary.BigEndian.AppendUint32(nil, value)
	data = binary.BigEndian.AppendUint32(data, id)
	attr := appendBandwidthAttr(nil, bwAttrVerdict, data)
	if err := sendBandwidthMessage(g.fd, bandwidthMessage(bwQueueVerdict, unix.NLM_F_REQUEST, 0, g.queue, attr)); err != nil {
		g.cancel()
	}
}

// Addresses are looked up only after verifying the real queue and hook/device.
// AWG's cryptokey routing verifies upload sources and selects download peers.
func (g *BandwidthGate) parseBandwidthPacket(data []byte) (bandwidthPacket, bool) {
	var packet bandwidthPacket
	if len(data) < 4 || data[1] != 0 || binary.BigEndian.Uint16(data[2:4]) != g.queue {
		return packet, false
	}
	isIPv4 := data[0] == unix.AF_INET
	var known, invalid bool
	var in, out, size, skb uint32
	var hook uint8
	var header []byte
	var seen uint16
	for data = data[4:]; len(data) > 0; {
		if len(data) < 4 {
			return packet, false
		}
		attrSize := int(binary.NativeEndian.Uint16(data[:2]))
		kind := binary.NativeEndian.Uint16(data[2:4])
		next := (attrSize + 3) &^ 3
		if attrSize < 4 || next > len(data) {
			return packet, false
		}
		value := data[4:attrSize]
		data = data[next:]
		if kind <= bwAttrSKB {
			bit := uint16(1) << kind
			invalid = invalid || (seen&bit != 0)
			seen |= bit
		}
		switch kind {
		case bwAttrPacket:
			if len(value) != 7 || known {
				return packet, false
			}
			packet.id = binary.BigEndian.Uint32(value)
			isIPv4 = isIPv4 && binary.BigEndian.Uint16(value[4:6]) == unix.ETH_P_IP
			hook = value[6]
			known = true
		case bwAttrPayload:
			header = value
		case bwAttrIn, bwAttrOut, bwAttrLength, bwAttrSKB:
			if len(value) != 4 {
				invalid = true
				continue
			}
			n := binary.BigEndian.Uint32(value)
			switch kind {
			case bwAttrIn:
				in = n
			case bwAttrOut:
				out = n
			case bwAttrLength:
				size = n
			case bwAttrSKB:
				skb = n
			}
		}
	}
	if !known || invalid || !isIPv4 || skb&bwPacketGSO != 0 || len(header) < 20 || header[0]>>4 != 4 {
		return packet, known
	}
	headerLen := int(header[0]&0xf) * 4
	total := int(binary.BigEndian.Uint16(header[2:4]))
	// Copy only the IPv4 header. For larger packets, CAP_LEN must confirm the
	// kernel's original length. Never charge the netlink attribute size.
	if headerLen < 20 || headerLen > len(header) || total < headerLen ||
		(size == 0 && total != len(header)) ||
		(size != 0 && (uint32(total) != size || len(header) != bwHeaderBytes || total <= len(header))) {
		return packet, true
	}
	var addr netip.Addr
	switch {
	case hook == unix.NF_INET_PRE_ROUTING && in == uint32(g.ifIndex):
		addr = netip.AddrFrom4([4]byte(header[12:16]))
	case hook == unix.NF_INET_POST_ROUTING && out == uint32(g.ifIndex):
		addr = netip.AddrFrom4([4]byte(header[16:20]))
	default:
		return packet, true
	}
	for _, route := range g.routes {
		if route.AllowedIP.Contains(addr) {
			packet.account, packet.bytes, packet.unmetered = route.AccountID, total, route.Unmetered
			break
		}
	}
	return packet, true
}
