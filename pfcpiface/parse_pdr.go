// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Intel Corporation
// Copyright 2022 Open Networking Foundation

package pfcpiface

import (
	"fmt"
	"math"
	"net"
	"net/netip"

	"github.com/omec-project/upf-epc/logger"
	"github.com/wmnsk/go-pfcp/ie"
)

// portRange encapsulates a L4 port range as seen in PDRs. A zero value portRange represents
// a wildcard match, but use of the dedicated new*PortRange() functions is encouraged.
type portRange struct {
	low  uint16
	high uint16
}

// newWildcardPortRange returns a portRange that matches on every possible port, i.e., implements
// no filtering.
func newWildcardPortRange() portRange {
	return portRange{
		low:  0,
		high: math.MaxUint16,
	}
}

// newExactMatchPortRange returns a portRange that matches on exactly the given port.
func newExactMatchPortRange(port uint16) portRange {
	return portRange{
		low:  port,
		high: port,
	}
}

// newRangeMatchPortRange returns a portRange that matches on the given range [low, high].
// low must be smaller than high. Creating exact and wildcard matches with this function is
// possible, but use of the dedicated functions is encouraged.
func newRangeMatchPortRange(low, high uint16) portRange {
	if low > high {
		return portRange{}
	}

	return portRange{
		low:  low,
		high: high,
	}
}

func (pr portRange) String() string {
	return fmt.Sprintf("{%v-%v}", pr.low, pr.high)
}

// Width returns the number of ports covered by this portRange.
func (pr portRange) Width() uint16 {
	// Need to handle the zero value.
	if pr.isWildcardMatch() {
		return math.MaxUint16
	} else {
		return pr.high - pr.low + 1
	}
}

// sameMatch reports whether both ranges reach the datapath as the same rule. "Any port"
// has two spellings -- the zero value, which a PDR carrying no SDF Filter keeps, and
// newWildcardPortRange(), which every filter path sets -- and asTrivialTernaryMatch
// compiles both to the same ternary rule.
func (pr portRange) sameMatch(other portRange) bool {
	return pr == other || pr.isWildcardMatch() && other.isWildcardMatch()
}

func (pr portRange) isWildcardMatch() bool {
	return pr.low == 0 && pr.high == math.MaxUint16 ||
		pr.low == 0 && pr.high == 0
}

func (pr portRange) isExactMatch() bool {
	return pr.low == pr.high && pr.high != 0
}

func (pr portRange) isRangeMatch() bool {
	return !pr.isExactMatch() && !pr.isWildcardMatch()
}

// Returns portRange as an exact match, without checking if it is one. isExactMatch() must be true
// before calling asExactMatchUnchecked.
func (pr portRange) asExactMatchUnchecked() portRangeTernaryRule {
	return portRangeTernaryRule{port: pr.low, mask: math.MaxUint16}
}

// Return portRange as a trivial, single value and mask, ternary match. Will fail if conversion is
// not possible.
func (pr portRange) asTrivialTernaryMatch() (portRangeTernaryRule, error) {
	if pr.isWildcardMatch() {
		return portRangeTernaryRule{0, 0}, nil
	} else if pr.isExactMatch() {
		return pr.asExactMatchUnchecked(), nil
	}

	return portRangeTernaryRule{}, ErrInvalidArgumentWithReason("asTrivialTernaryMatch", pr, "not trivially convertible")
}

type RangeConversionStrategy int

const (
	Exact RangeConversionStrategy = iota
	Ternary
)

// Returns portRange as a list of ternary matches that cover the same range.
func (pr portRange) asComplexTernaryMatches(strategy RangeConversionStrategy) ([]portRangeTernaryRule, error) {
	rules := make([]portRangeTernaryRule, 0)

	// Fast path for exact and wildcard matches which are trivial.
	if pr.isExactMatch() {
		rules = append(rules, pr.asExactMatchUnchecked())
		return rules, nil
	}

	if pr.isWildcardMatch() {
		rules = append(rules, portRangeTernaryRule{0, 0})
		return rules, nil
	}

	switch strategy {
	case Exact:
		if pr.Width() > 100 {
			return nil, ErrInvalidArgumentWithReason("asComplexTernaryMatches", pr,
				"port range too wide for exact match strategy")
		}

		for port := int(pr.low); port <= int(pr.high); port++ {
			rules = append(rules, portRangeTernaryRule{uint16(port), math.MaxUint16})
		}
	case Ternary:
		// Adapted from https://stackoverflow.com/a/66959276
		return pr.buildTernaryRules(), nil
	default:
		return nil, ErrInvalidArgument("asComplexTernaryMatches", strategy)
	}

	return rules, nil
}

func (pr portRange) buildTernaryRules() []portRangeTernaryRule {
	const limit = math.MaxUint16
	maxPort := func(port, mask uint16) uint16 {
		xid := limit - mask
		nid := port & mask
		return nid + xid
	}

	portMask := func(port, end uint16) uint16 {
		bit := uint16(1)
		mask := uint16(limit)
		testMask := uint16(limit)
		netPort := port & limit
		maximumPort := maxPort(netPort, limit)

		for netPort > 0 && maximumPort < end {
			netPort = port & testMask
			if netPort < port {
				break
			}
			maximumPort = maxPort(netPort, testMask)
			if maximumPort <= end {
				mask = testMask
			}
			testMask -= bit
			bit <<= 1
		}
		return mask
	}

	rules := make([]portRangeTernaryRule, 0)
	port := uint32(pr.low) // Promote to higher bit width for greater-equals check.
	for port <= uint32(pr.high) {
		mask := portMask(uint16(port), pr.high)
		rules = append(rules, portRangeTernaryRule{uint16(port), mask})
		port = uint32(maxPort(uint16(port), mask)) + 1
	}
	return rules
}

type portRangeTernaryRule struct {
	port, mask uint16
}

func (pf portRangeTernaryRule) String() string {
	return fmt.Sprintf("{0b%b & 0b%b}", pf.port, pf.mask)
}

type portRangeTernaryCartesianProduct struct {
	srcPort, srcMask uint16
	dstPort, dstMask uint16
}

// CreatePortRangeCartesianProduct converts two port ranges into a list of ternary
// rules covering the same range.
func CreatePortRangeCartesianProduct(src, dst portRange) ([]portRangeTernaryCartesianProduct, error) {
	// A single range rule can result in multiple ternary ones. To cover the same range of packets,
	// we need to create the Cartesian product of src and dst rules. For now, we only allow one true
	// range match to keep the complexity in check.
	if src.isRangeMatch() && dst.isRangeMatch() {
		return nil, ErrInvalidArgumentWithReason("CreatePortRangeCartesianProduct",
			src, "src and dst ports cannot both be a range match")
	}

	rules := make([]portRangeTernaryCartesianProduct, 0)

	if src.isRangeMatch() {
		srcTernaryRules, err := src.asComplexTernaryMatches(Exact)
		if err != nil {
			return nil, err
		}

		dstTernary, err := dst.asTrivialTernaryMatch()
		if err != nil {
			return nil, err
		}
		rules = buildRulesFromRange(srcTernaryRules, dstTernary, true)
	} else if dst.isRangeMatch() {
		dstTernaryRules, err := dst.asComplexTernaryMatches(Exact)
		if err != nil {
			return nil, err
		}

		srcTernary, err := src.asTrivialTernaryMatch()
		if err != nil {
			return nil, err
		}

		rules = buildRulesFromRange(dstTernaryRules, srcTernary, false)
	} else {
		// Neither is range. Only one rule needed.
		srcTernary, err := src.asTrivialTernaryMatch()
		if err != nil {
			return nil, err
		}

		dstTernary, err := dst.asTrivialTernaryMatch()
		if err != nil {
			return nil, err
		}

		p := portRangeTernaryCartesianProduct{
			dstPort: dstTernary.port, dstMask: dstTernary.mask,
			srcPort: srcTernary.port, srcMask: srcTernary.mask,
		}
		rules = append(rules, p)
	}

	return rules, nil
}

func buildRulesFromRange(
	rangeRules []portRangeTernaryRule,
	fixedRule portRangeTernaryRule,
	isSrcRange bool,
) []portRangeTernaryCartesianProduct {
	rules := make([]portRangeTernaryCartesianProduct, 0, len(rangeRules))
	for _, r := range rangeRules {
		if isSrcRange {
			rules = append(rules, portRangeTernaryCartesianProduct{
				srcPort: r.port, srcMask: r.mask,
				dstPort: fixedRule.port, dstMask: fixedRule.mask,
			})
		} else {
			rules = append(rules, portRangeTernaryCartesianProduct{
				srcPort: fixedRule.port, srcMask: fixedRule.mask,
				dstPort: r.port, dstMask: r.mask,
			})
		}
	}

	return rules
}

// applicationFilter is the part of a PDR's match that is about the packet itself. The
// addresses are match prefixes (see matchPrefix): the zero Prefix matches any address.
type applicationFilter struct {
	srcIP        netip.Prefix
	dstIP        netip.Prefix
	srcPortRange portRange
	dstPortRange portRange
	proto        uint8

	protoMask uint8
}

type pdr struct {
	UPAllocateFteid bool
	srcIface        uint8
	// tunnelIPDst is the F-TEID address the PDR matches GTP-U packets on, as a host
	// prefix; the zero Prefix matches any.
	tunnelIPDst netip.Prefix
	// tunnelIPv6Dst is the IPv6 address of the F-TEID, when it has one. It is parsed but
	// not matched on: the datapath forwards IPv4 only.
	tunnelIPv6Dst netip.Prefix
	tunnelTEID    uint32
	// ueAddress is the UE's IPv4 address; the zero Addr when the PDR names none.
	ueAddress netip.Addr
	// ueIPv6 is the UE's IPv6 prefix, with the address the control plane sent (prefix and
	// interface identifier); the zero Prefix when the PDR names none. Parsed, not
	// installed: see checkDatapathSupport.
	ueIPv6 netip.Prefix

	srcIfaceMask   uint8
	tunnelTEIDMask uint32

	appFilter applicationFilter
	// noIPv4Rule says the PDR's filter names IPv6 addresses only: it matches no IPv4
	// packet, and appFilter is not a rule.
	noIPv4Rule bool
	// appFilter6 is the match for the PDR's IPv6 packets, when hasIPv6Rule says it has
	// one: the UE has an IPv6 prefix, or the filter names IPv6 addresses. Parsed, not
	// installed: see checkDatapathSupport.
	appFilter6  applicationFilter
	hasIPv6Rule bool

	precedence  uint32
	pdrID       uint32
	fseID       uint64
	fseidIP     netip.Addr
	ctrID       uint32
	farID       uint32
	qerIDList   []uint32
	needDecap   uint8
	allocIPFlag bool

	// chooseID groups the PDRs of one message that are to share the F-TEID allocated for
	// them, when hasChooseID says the control plane sent one (TS 29.244 clause 5.5.3).
	chooseID    uint8
	hasChooseID bool
}

// needAllocIP reports whether a UE IP Address IE asks the UP function to choose the UE's
// IPv4 address. That is the CHV4 flag alone (TS 29.244 clause 8.2.62, octet 5 bit 5):
// with it the IE carries no IPv4 address. V4 shall not be set beside it; a sender that
// sets it anyway is still asking for an address, and go-pfcp decodes none. An IE
// that carries no IPv4 address is not by that alone a request for one -- it may be
// IPv6-only -- and CHV6 asks for an IPv6 address, which is not allocated here.
func needAllocIP(ueIPaddr *ie.UEIPAddressFields) bool {
	return has5thBit(ueIPaddr.Flags)
}

func (af applicationFilter) String() string {
	return fmt.Sprintf("ApplicationFilter(srcIP=%v, dstIP=%v, proto=%v/%x, srcPort=%v, dstPort=%v)",
		af.srcIP, af.dstIP, af.proto, af.protoMask, af.srcPortRange, af.dstPortRange)
}

// occupiesSameEntryAs reports whether both rules would land on the same datapath entry.
//
// The fields compared here are the ones delPDR builds its delete key from (bess.go): the
// source interface, the tunnel it arrives on, and the application filter, each with its
// mask. Precedence is written as the entry's priority and the PDR ID as one of its
// values, and neither is part of the key -- so a rule can change either and still occupy
// the entry it already had. If the delete key ever gains a field, it has to gain one
// here too.
//
// The ports are compared through sameMatch rather than by value, because delPDR keys on
// what CreatePortRangeCartesianProduct makes of a range, not on the range itself.
func (p pdr) occupiesSameEntryAs(other pdr) bool {
	return p.srcIface == other.srcIface &&
		p.srcIfaceMask == other.srcIfaceMask &&
		p.tunnelIPDst == other.tunnelIPDst &&
		p.tunnelTEID == other.tunnelTEID &&
		p.tunnelTEIDMask == other.tunnelTEIDMask &&
		p.appFilter.srcIP == other.appFilter.srcIP &&
		p.appFilter.dstIP == other.appFilter.dstIP &&
		p.appFilter.proto == other.appFilter.proto &&
		p.appFilter.protoMask == other.appFilter.protoMask &&
		p.appFilter.srcPortRange.sameMatch(other.appFilter.srcPortRange) &&
		p.appFilter.dstPortRange.sameMatch(other.appFilter.dstPortRange)
}

func (p pdr) String() string {
	s := fmt.Sprintf("PDR(id=%v, F-SEID=%v, srcIface=%v, tunnelIPDst=%v, "+
		"tunnelTEID=%v/%x, ueAddress=%v, applicationFilter=%v, precedence=%v, F-SEID IP=%v, "+
		"counterID=%v, farID=%v, qerIDs=%v, needDecap=%v, allocIPFlag=%v",
		p.pdrID, p.fseID, p.srcIface, p.tunnelIPDst,
		p.tunnelTEID, p.tunnelTEIDMask, p.ueAddress, p.appFilter, p.precedence,
		p.fseidIP, p.ctrID, p.farID, p.qerIDList, p.needDecap, p.allocIPFlag)

	// The IPv6 parts, which are not installed, only when there are any.
	if p.tunnelIPv6Dst.IsValid() {
		s += fmt.Sprintf(", tunnelIPv6Dst=%v", p.tunnelIPv6Dst)
	}

	if p.ueIPv6.IsValid() {
		s += fmt.Sprintf(", ueIPv6=%v", p.ueIPv6)
	}

	if p.noIPv4Rule {
		s += ", noIPv4Rule"
	}

	if p.hasIPv6Rule {
		s += fmt.Sprintf(", applicationFilter6=%v", p.appFilter6)
	}

	return s + ")"
}

func (p pdr) IsAppFilterEmpty() bool {
	return p.appFilter.proto == 0 &&
		((p.IsUplink() && isZeroAddr(p.appFilter.dstIP.Addr()) && p.appFilter.dstPortRange.isWildcardMatch()) ||
			(p.IsDownlink() && isZeroAddr(p.appFilter.srcIP.Addr()) && p.appFilter.srcPortRange.isWildcardMatch()))
}

func (p pdr) IsUplink() bool {
	return p.srcIface == access
}

func (p pdr) IsDownlink() bool {
	return p.srcIface == core
}

func (p *pdr) parseUEAddressIE(ueAddrIE *ie.IE, ippool *IPPool) error {
	var ueIP4 net.IP

	ueIPaddr, err := ueAddrIE.UEIPAddress()
	if err != nil {
		return err
	}

	flags := ueIPaddr.Flags

	// The IPv6 part is read first: it allocates nothing, so a malformed one is refused
	// before an IPv4 address is taken out of the pool.
	ueIPv6, err := parseUEIPv6(ueIPaddr)
	if err != nil {
		return err
	}

	switch {
	case needAllocIP(ueIPaddr):
		logger.PfcpLog.Infof("UPF should alloc UE IP for SEID %v. CHV4 flag set", p.fseID)

		ueIP4, err = ippool.LookupOrAllocIP(p.fseID)
		if err != nil {
			logger.PfcpLog.Errorln("failed to allocate UE IP:", err)
			return err
		}

		logger.PfcpLog.Debugln("found or allocated new IP", ueIP4, "from pool", ippool)

		p.allocIPFlag = true
	case has2ndBit(flags):
		ueIP4 = ueIPaddr.IPv4Address
	case ueIPv6.IsValid():
		// IPv6-only. The address is kept; checkDatapathSupport refuses the PDR.
		p.ueIPv6 = ueIPv6

		return nil
	case has6thBit(flags):
		// CHV6 alone: the UPF is to choose the UE's IPv6 prefix, which it cannot do, and
		// there is no IPv4 part.
		return ErrUnsupported("UE IP Address IE asking the UP function to choose an IPv6 prefix (CHV6), flags",
			fmt.Sprintf("0x%02x", flags))
	default:
		return ErrInvalidArgumentWithReason("UE IP Address IE flags", fmt.Sprintf("0x%02x", flags),
			"neither an address nor CHV4/CHV6 is set")
	}

	// IPv4v6: both parts are kept, and the datapath installs the IPv4 one, as before. A
	// CHV6 beside it is not answered: the Created PDR reports no IPv6 prefix, so a
	// control plane that asked the UPF to choose one can see that it was not chosen.
	if ueIPv6.IsValid() || has6thBit(flags) {
		logger.PfcpLog.Warnf("the IPv6 part of the UE IP Address IE for SEID %v (flags 0x%02x, "+
			"prefix %v) is not installed: the datapath forwards IPv4 only", p.fseID, flags, ueIPv6)
	}

	// Needed if SDF filter is bad or absent
	if len(ueIP4) != 4 {
		return ErrOperationFailedWithParam("parse UE Address IE",
			"IP address length", len(ueIP4))
	}

	p.ueAddress = addrFromIP(ueIP4)
	p.ueIPv6 = ueIPv6

	return nil
}

// defaultUEIPv6PrefixLength is the length of a UE IPv6 prefix whose UE IP Address IE does
// not give one (TS 29.244 clause 8.2.62, and TS 23.501 clause 5.8.2.2.2: a /64 per PDU
// session).
const defaultUEIPv6PrefixLength = 64

// parseUEIPv6 returns the IPv6 part of a UE IP Address IE: the address as the control
// plane sent it -- an SMF sends the UE's full address, prefix and interface identifier --
// with the prefix length from the IPv6 Prefix Length field (IP6PL), or /64 without one.
// The prefix is not masked, so the interface identifier survives; a match uses the
// masked prefix. An IE without an IPv6 address gives the zero Prefix.
func parseUEIPv6(f *ie.UEIPAddressFields) (netip.Prefix, error) {
	if !has1stBit(f.Flags) {
		return netip.Prefix{}, nil
	}

	a := addrFromIP(f.IPv6Address)
	if isZeroAddr(a) {
		// V6 with no address, as some senders set it beside CHV6.
		return netip.Prefix{}, nil
	}

	if !a.Is6() {
		return netip.Prefix{}, ErrInvalidArgumentWithReason("UE IP Address IE IPv6 address", a,
			"an IPv4-mapped address")
	}

	if has4thBit(f.Flags) {
		// IPv6D: prefix delegation, which neither the SMF nor this UPF does.
		return netip.Prefix{}, ErrUnsupported("UE IP Address IE with IPv6 prefix delegation (IPv6D), bits",
			f.IPv6PrefixDelegationBits)
	}

	bits := defaultUEIPv6PrefixLength

	if has7thBit(f.Flags) {
		bits = int(f.IPv6PrefixLength)
		if bits == 0 || bits > 128 {
			return netip.Prefix{}, ErrInvalidArgumentWithReason("UE IP Address IE IPv6 prefix length", bits,
				"not between 1 and 128")
		}
	}

	return netip.PrefixFrom(a, bits), nil
}

func (p *pdr) parseSourceInterfaceIE(srcIfaceIE *ie.IE) error {
	srcIface, err := srcIfaceIE.SourceInterface()
	if err != nil {
		return err
	}

	switch srcIface {
	case ie.SrcInterfaceCPFunction:
		return ErrUnsupported("Source Interface CP Function", srcIface)
	case ie.SrcInterfaceAccess:
		p.srcIface = access
		p.srcIfaceMask = 0xFF
	case ie.SrcInterfaceCore:
		p.srcIface = core
		p.srcIfaceMask = 0xFF
	}

	return nil
}

func (p *pdr) parseFTEID(teidIE *ie.IE) error {
	fteid, err := teidIE.FTEID()
	if err != nil {
		return err
	}

	teid := fteid.TEID
	if fteid.HasCh() {
		// CHOOSE with only the V6 flag asks for an IPv6 F-TEID (TS 29.244 clause 8.2.3).
		// The UPF has none to give; it used to answer with its IPv4 one.
		if fteid.HasIPv6() && !fteid.HasIPv4() {
			return ErrUnsupported("F-TEID asking the UP function to choose an IPv6 address, flags",
				fmt.Sprintf("0x%02x", fteid.Flags))
		}

		p.UPAllocateFteid = true
		if fteid.HasChID() {
			p.chooseID = fteid.ChooseID
			p.hasChooseID = true
		}
	} else if teid != 0 {
		p.tunnelTEID = teid
		p.tunnelTEIDMask = 0xFFFFFFFF
		p.tunnelIPDst = hostPrefix(addrFromIP(fteid.IPv4Address))

		if fteid.HasIPv6() {
			p.tunnelIPv6Dst = hostPrefix(addrFromIP(fteid.IPv6Address))
		}
	}

	return nil
}

func (p *pdr) parseApplicationID(ie *ie.IE, appPFDs map[string]appPFD) error {
	appID, err := ie.ApplicationID()
	if err != nil {
		return err
	}

	apfd, ok := appPFDs[appID]
	if !ok {
		return ErrNotFoundWithParam("Application PFD for ApplicationID", "application ID", appID)
	}

	if appID != apfd.appID {
		logger.PfcpLog.Fatalln("mismatch in App ID", appID, apfd.appID)
	}

	for _, flowDesc := range apfd.flowDescs {
		logger := logger.PfcpLog.With("Application ID", apfd.appID, "Flow Description", flowDesc)
		logger.Debug("Parsing flow description of Application ID IE")

		ipf, err := parseFlowDesc(flowDesc)
		if err != nil {
			return fmt.Errorf("%w: %q: %w", errBadFilterDesc, flowDesc, err)
		}

		if (p.srcIface == access && ipf.direction == filterDirectionOut) ||
			(p.srcIface == core && ipf.direction == filterDirectionIn) {
			logger.Debug("Found a matching flow description")

			// TODO: Verify assumption that flow description in case of PFD is to be taken as-is
			p.applyFlow(ipf, ipf.src, ipf.dst, nil)

			return nil
		}
	}

	return nil
}

// safeSDFFilter wraps i.SDFFilter() to convert the go-pfcp ≤ v0.0.24
// slice-bounds panic into an ordinary error. SDFFilterFields.UnmarshalBinary
// fails to validate FDLength against the remaining payload bytes.
func safeSDFFilter(i *ie.IE) (fields *ie.SDFFilterFields, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("SDF Filter IE malformed (panic while parsing): %v", r)
		}
	}()
	return i.SDFFilter()
}

func (p *pdr) parseSDFFilter(ie *ie.IE) error {
	sdfFields, err := safeSDFFilter(ie)
	if err != nil {
		return err
	}

	flowDesc := sdfFields.FlowDescription
	if flowDesc == "" {
		return ErrOperationFailedWithReason("parse SDF Filter", "empty filter description")
	}

	logger.PfcpLog.With("Flow Description", flowDesc).Debugln("parsing Flow Description from SDF Filter")

	ipf, err := parseFlowDesc(flowDesc)
	if err != nil {
		return fmt.Errorf("%w: %q: %w", errBadFilterDesc, flowDesc, err)
	}

	switch p.srcIface {
	case core:
		p.applyFlow(ipf, ipf.src, ipf.dst, func(af *applicationFilter) {
			// TODO: temporary workaround for SDF Filter,
			//  remove once we meet spec compliance
			if !af.dstPortRange.isWildcardMatch() {
				af.srcPortRange = af.dstPortRange
				af.dstPortRange = newWildcardPortRange()
			}
		})
	case access:
		// Addresses and ports are flipped for access PDRs
		p.applyFlow(ipf, ipf.dst, ipf.src, func(af *applicationFilter) {
			// TODO: temporary workaround for SDF Filter,
			//  remove once we meet spec compliance
			if !af.srcPortRange.isWildcardMatch() {
				af.dstPortRange = af.srcPortRange
				af.srcPortRange = newWildcardPortRange()
			}
		})
	}

	return nil
}

// applyFlow sets the PDR's application filters from a flow rule. src and dst are the
// rule's endpoints in the order the filter's source and destination take them, and
// adjust, when given, is applied to each filter set.
//
// A rule is applied once per address family it covers. One that names IPv4 addresses
// is the IPv4 filter alone, one that names IPv6 addresses the IPv6 filter alone, and
// one that names none ("any", "assigned") is both -- the IPv6 one only for a UE with an
// IPv6 prefix. "assigned" is the UE's address of the filter's family.
func (p *pdr) applyFlow(ipf *ipFilterRule, src, dst endpoint, adjust func(*applicationFilter)) {
	set := func(af *applicationFilter, ue netip.Prefix) {
		if ipf.proto != reservedProto {
			af.proto = ipf.proto
			af.protoMask = math.MaxUint8
		}

		af.srcIP = src.matchFor(ue)
		af.dstIP = dst.matchFor(ue)
		af.srcPortRange = src.ports
		af.dstPortRange = dst.ports

		if adjust != nil {
			adjust(af)
		}
	}

	family := ipf.family()

	p.noIPv4Rule = family == 6
	if !p.noIPv4Rule {
		set(&p.appFilter, p.ueIPv4Match())
	}

	p.hasIPv6Rule = family == 6 || family == 0 && p.ueIPv6.IsValid()
	if p.hasIPv6Rule {
		set(&p.appFilter6, p.ueIPv6.Masked())
	} else {
		p.appFilter6 = applicationFilter{}
	}
}

// ueIPv4Match is what the UE's IPv4 address matches as: itself, or any address when the
// PDR names none.
func (p pdr) ueIPv4Match() netip.Prefix {
	if isZeroAddr(p.ueAddress) {
		return netip.Prefix{}
	}

	return hostPrefix(p.ueAddress)
}

func (p *pdr) parsePDI(pdiIEs []*ie.IE, appPFDs map[string]appPFD, ippool *IPPool) error {
	if err := p.processBasicPDI(pdiIEs, ippool); err != nil {
		return err
	}
	// initialize application filter with UE address;
	// it can be overwritten by parseSDFFilter() later.
	if p.IsDownlink() && !isZeroAddr(p.ueAddress) {
		p.appFilter.dstIP = hostPrefix(p.ueAddress)
	} else if p.IsUplink() && !isZeroAddr(p.ueAddress) {
		p.appFilter.srcIP = hostPrefix(p.ueAddress)
	}

	// The same for the UE's IPv6 prefix: the UE may use any address in it.
	if p.ueIPv6.IsValid() && (p.IsDownlink() || p.IsUplink()) {
		p.hasIPv6Rule = true

		if p.IsDownlink() {
			p.appFilter6.dstIP = p.ueIPv6.Masked()
		} else {
			p.appFilter6.srcIP = p.ueIPv6.Masked()
		}
	}

	// make another iteration because Application ID and SDF Filter depend on UE IP Address IE
	for _, ie2 := range pdiIEs {
		switch ie2.Type {
		case ie.ApplicationID:
			if err := p.parseApplicationID(ie2, appPFDs); err != nil {
				logger.PfcpLog.Errorf("failed to parse Application ID IE: %v", err)
				return err
			}
		case ie.SDFFilter:
			if err := p.parseSDFFilter(ie2); err != nil {
				logger.PfcpLog.Errorf("failed to parse SDF Filter IE: %v", err)
				return err
			}
		}
	}

	return nil
}

func (p *pdr) processBasicPDI(pdiIEs []*ie.IE, ippool *IPPool) error {
	for _, pdiIE := range pdiIEs {
		switch pdiIE.Type {
		case ie.UEIPAddress:
			if err := p.parseUEAddressIE(pdiIE, ippool); err != nil {
				logger.PfcpLog.Errorf("failed to parse UE Address IE: %v", err)
				return err
			}
		case ie.SourceInterface:
			if err := p.parseSourceInterfaceIE(pdiIE); err != nil {
				logger.PfcpLog.Errorf("failed to parse Source Interface IE: %v", err)
				return err
			}
		case ie.FTEID:
			if err := p.parseFTEID(pdiIE); err != nil {
				logger.PfcpLog.Errorf("failed to parse F-TEID IE: %v", err)
				return err
			}
		}
	}
	return nil
}

func (p *pdr) parsePDR(ie1 *ie.IE, seid uint64, appPFDs map[string]appPFD, ippool *IPPool) error {
	/* reset outerHeaderRemoval to begin with */
	outerHeaderRemoval := uint8(0)
	p.qerIDList = make([]uint32, 0)
	p.fseID = seid

	pdrID, precedence, farID, outerHeaderRemoval, err := p.parseCorePDRFields(ie1, appPFDs, ippool)
	if err != nil {
		return err
	}

	/* Multiple instances of QERID can be present in CreatePDR/UpdatePDR
	   go-pfcp currently support API to return list of QERIDs. So, we
	   are parsing the IE list in Application code.*/
	var ies []*ie.IE

	var errin error

	switch ie1.Type {
	case ie.CreatePDR:
		ies, errin = ie1.CreatePDR()
		if errin != nil {
			return errin
		}
	case ie.UpdatePDR:
		ies, errin = ie1.UpdatePDR()
		if errin != nil {
			return errin
		}
	}

	for _, x := range ies {
		if x.Type == ie.QERID {
			qerID, errRead := x.QERID()
			if errRead != nil {
				logger.PfcpLog.Errorln("qerID read failed")
				continue
			} else {
				p.qerIDList = append(p.qerIDList, qerID)
			}
		}
	}
	/*qerID, err := ie1.QERID()
	if err != nil {
		logger.PfcpLog.Errorln("could not read QER ID!")
	}*/

	p.precedence = precedence
	p.pdrID = uint32(pdrID)
	p.farID = farID // farID currently not being set <--- FIXIT/TODO/XXX
	/*p.qerID = qerID*/
	p.needDecap = outerHeaderRemoval

	return p.checkDatapathSupport()
}

// Outer Header Removal Descriptions (TS 29.244 clause 8.2.64). GTP-U/UDP/IP (6), either
// family, leaves needDecap clear, as it always has.
const (
	ohrGtpUUdpIPv4 = 0
	ohrGtpUUdpIPv6 = 1
	ohrUDPIPv6     = 3
	ohrIPv6        = 5
)

// checkDatapathSupport refuses a PDR the datapath cannot match as the control plane
// meant it. The datapath matches IPv4 only, so a PDR that matches only IPv6 traffic
// would be installed matching something else, or everything: it is refused here, where
// the refusal reaches the control plane as Request rejected, rather than as a datapath
// write that fails. The IPv6 part of a PDR that also matches IPv4 -- an IPv4v6 UE, an
// F-TEID with both addresses -- is kept in the rule and not installed.
func (p pdr) checkDatapathSupport() error {
	if p.ueIPv6.IsValid() && !p.ueAddress.IsValid() {
		return ErrUnsupported("PDR for an IPv6-only UE address", p.ueIPv6)
	}

	if p.noIPv4Rule {
		return ErrUnsupported("PDR whose filter matches IPv6 only", p.appFilter6)
	}

	if p.tunnelIPv6Dst.IsValid() && !p.tunnelIPDst.IsValid() {
		return ErrUnsupported("PDR on an IPv6-only F-TEID", p.tunnelIPv6Dst)
	}

	for _, a := range []netip.Prefix{p.tunnelIPDst, p.appFilter.srcIP, p.appFilter.dstIP} {
		if a.IsValid() && !a.Addr().Is4() {
			return ErrUnsupported("PDR matching an IPv6 address", a)
		}
	}

	return nil
}

func (p *pdr) parseCorePDRFields(
	ie1 *ie.IE,
	appPFDs map[string]appPFD,
	ippool *IPPool,
) (uint16, uint32, uint32, uint8, error) {
	var outerHeaderRemoval uint8
	pdrID, err := ie1.PDRID()
	if err != nil {
		logger.PfcpLog.Errorln("could not read PDR ID!")
		return 0, 0, 0, 0, err
	}

	precedence, err := ie1.Precedence()
	if err != nil {
		logger.PfcpLog.Errorln("could not read Precedence!")
		return 0, 0, 0, 0, err
	}

	pdi, err := ie1.PDI()
	if err != nil {
		logger.PfcpLog.Errorln("could not read PDI!")
		return 0, 0, 0, 0, err
	}

	res, err := ie1.OuterHeaderRemovalDescription()
	if err == nil {
		switch res {
		case ohrGtpUUdpIPv4:
			outerHeaderRemoval = 1
		case ohrGtpUUdpIPv6, ohrUDPIPv6, ohrIPv6:
			// The datapath parses IPv4 outer headers only: a PDR on IPv6 ones would
			// never match, or would be matched on the wrong header.
			return 0, 0, 0, 0, ErrUnsupported("Outer Header Removal of an IPv6 header, description", res)
		}
	}

	// A filter that does not parse refuses the PDR. It used to be installed without the
	// filter, matching what the filter was there to exclude.
	err = p.parsePDI(pdi, appPFDs, ippool)
	if err != nil {
		return 0, 0, 0, 0, err
	}

	farID, err := ie1.FARID()
	if err != nil {
		logger.PfcpLog.Errorln("could not read FAR ID!")
		return 0, 0, 0, 0, err
	}
	return pdrID, precedence, farID, outerHeaderRemoval, nil
}
