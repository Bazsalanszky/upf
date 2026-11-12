// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Intel Corporation
// Copyright 2022 Open Networking Foundation

package pfcpiface

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/omec-project/upf-epc/logger"
)

const (
	reservedProto = uint8(0xff)

	filterActionPermit = "permit"
	filterActionDeny   = "deny"
	filterDirectionIn  = "in"
	filterDirectionOut = "out"
)

var errBadFilterDesc = errors.New("unsupported Filter Description format")

// endpoint is one side of a flow description (TS 29.212 clause 5.4.2, IPFilterRule of
// RFC 6733): "any", "assigned", or an address or prefix of either family.
type endpoint struct {
	// prefix is the address or prefix the flow names, its host bits cleared; a bare
	// address is a /32 or a /128. The zero Prefix is "any" (or "assigned"): any address
	// of whichever family the rule is applied to.
	prefix netip.Prefix
	// assigned is "assigned": the UE's address of the family the rule is applied to.
	assigned bool
	ports    portRange
}

func (ep *endpoint) parseNet(ipnet string) error {
	switch ipnet {
	case "any":
		return nil
	case "assigned":
		ep.assigned = true
		return nil
	}

	if strings.Contains(ipnet, "/") {
		p, err := netip.ParsePrefix(ipnet)
		if err != nil {
			return ErrOperationFailedWithReason("ParsePrefix", err.Error())
		}

		ep.prefix = p.Masked()

		return nil
	}

	a, err := netip.ParseAddr(ipnet)
	if err != nil {
		return ErrOperationFailedWithReason("ParseAddr", err.Error())
	}

	if a.Zone() != "" {
		return ErrInvalidArgumentWithReason("network string", ipnet, "a scoped address")
	}

	ep.prefix = hostPrefix(a)

	return nil
}

// family is the address family the endpoint names: 4, 6, or 0 for "any" and "assigned".
func (ep endpoint) family() int {
	switch {
	case !ep.prefix.IsValid():
		return 0
	case ep.prefix.Addr().Is4():
		return 4
	default:
		return 6
	}
}

// matchFor returns what the endpoint matches when the rule is applied to traffic of one
// family: "any" is any address; "assigned" is ue, the UE's address or prefix of that
// family, or any address when the UE has none -- as it was before the families were
// told apart; an address or prefix is itself.
func (ep endpoint) matchFor(ue netip.Prefix) netip.Prefix {
	if ep.assigned {
		return matchPrefix(ue)
	}

	return matchPrefix(ep.prefix)
}

func (ep *endpoint) parsePort(port string) error {
	ports := strings.Split(port, "-")
	if len(ports) == 0 || len(ports) > 2 {
		return ErrInvalidArgument("port string", port)
	}
	// Pretend this is a port range with one element.
	if len(ports) == 1 {
		ports = append(ports, ports[0])
	}

	low, err := strconv.ParseUint(ports[0], 10, 16)
	if err != nil {
		return err
	}

	high, err := strconv.ParseUint(ports[1], 10, 16)
	if err != nil {
		return err
	}

	if low > high {
		return ErrInvalidArgumentWithReason("port", port, "invalid port range")
	}

	ep.ports = newRangeMatchPortRange(uint16(low), uint16(high))

	return nil
}

type ipFilterRule struct {
	action, direction string
	proto             uint8
	src, dst          endpoint
}

func newIpFilterRule() *ipFilterRule {
	return &ipFilterRule{
		src: endpoint{ports: newWildcardPortRange()},
		dst: endpoint{ports: newWildcardPortRange()},
	}
}

func (ipf *ipFilterRule) String() string {
	return fmt.Sprintf("FlowDescription{action=%v, direction=%v, proto=%v, "+
		"srcIP=%v, srcPort=%v, dstIP=%v, dstPort=%v}",
		ipf.action, ipf.direction, ipf.proto, ipf.src, ipf.src.ports, ipf.dst, ipf.dst.ports)
}

func (ep endpoint) String() string {
	switch {
	case ep.assigned:
		return "assigned"
	case !ep.prefix.IsValid():
		return "any"
	default:
		return ep.prefix.String()
	}
}

// family is the address family the rule's addresses name: 4 or 6, or 0 when it names
// none ("any" and "assigned" only), and then applies to both.
func (ipf *ipFilterRule) family() int {
	return max(ipf.src.family(), ipf.dst.family())
}

// parseFlowDesc parses a flow description. "any" and "assigned" are kept as such: which
// address they stand for depends on the family the rule is applied to, and a rule that
// names no address applies to both.
func parseFlowDesc(flowDesc string) (*ipFilterRule, error) {
	parseLog := logger.PfcpLog.With("flow-description", flowDesc)
	parseLog.Debugln("parsing flow description")

	ipf := newIpFilterRule()

	fields := strings.Fields(flowDesc)
	if len(fields) < 3 {
		return nil, errBadFilterDesc
	}

	if err := parseAction(fields[0]); err != nil {
		return nil, err
	}

	ipf.action = fields[0]

	if err := parseDirection(fields[1]); err != nil {
		return nil, err
	}

	ipf.direction = fields[1]
	proto, err := parseL4Proto(fields[2])
	if err != nil {
		return nil, err
	}
	ipf.proto = proto

	if err := processFlowFields(fields, ipf, parseLog); err != nil {
		return nil, err
	}

	if src, dst := ipf.src.family(), ipf.dst.family(); src != 0 && dst != 0 && src != dst {
		parseLog.Errorln("the endpoints are of different address families")
		return nil, errBadFilterDesc
	}

	parseLog = parseLog.With("ip-filter", ipf)
	parseLog.Debugln("flow description parsed successfully")

	return ipf, nil
}

func processFlowFields(fields []string, ipf *ipFilterRule, parseLog interface{ Errorln(...any) }) error {
	for i := 3; i < len(fields); i++ {
		switch fields[i] {
		case "from":
			i++
			if i >= len(fields) {
				return errBadFilterDesc
			}

			err := ipf.src.parseNet(fields[i])
			if err != nil {
				parseLog.Errorln(err)
				return err
			}

			if i+1 < len(fields) && fields[i+1] != "to" {
				i++
				if i >= len(fields) {
					return errBadFilterDesc
				}
				err := ipf.src.parsePort(fields[i])
				if err != nil {
					parseLog.Errorln("src port parse failed", err)
					return err
				}
			}
		case "to":
			i++
			if i >= len(fields) {
				return errBadFilterDesc
			}

			err := ipf.dst.parseNet(fields[i])
			if err != nil {
				parseLog.Errorln(err)
				return err
			}

			if i+1 < len(fields) {
				i++
				if i >= len(fields) {
					return errBadFilterDesc
				}
				err := ipf.dst.parsePort(fields[i])
				if err != nil {
					parseLog.Errorln("dst port parse failed", err)
					return err
				}
			}
		}
	}
	return nil
}

func parseAction(action string) error {
	switch action {
	case filterActionPermit:
	case filterActionDeny:
	default:
		return errBadFilterDesc
	}

	return nil
}

func parseDirection(dir string) error {
	switch dir {
	case filterDirectionIn:
	case filterDirectionOut:
	default:
		return errBadFilterDesc
	}

	return nil
}

func parseL4Proto(proto string) (uint8, error) {
	p, err := strconv.ParseUint(proto, 10, 8)
	if err == nil {
		return uint8(p), nil
	}

	switch proto {
	case "ip":
		return reservedProto, nil
	case "udp":
		return 17, nil
	case "tcp":
		return 6, nil
	default:
		return reservedProto, errBadFilterDesc
	}
}
