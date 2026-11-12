// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Intel Corporation

package pfcpiface

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/omec-project/upf-epc/logger"
	"github.com/wmnsk/go-pfcp/ie"
)

// QosConfigVal : Qos configured value.
type QosConfigVal struct {
	cbs              uint32
	pbs              uint32
	ebs              uint32
	burstDurationMs  uint32
	schedulePriority uint32
}

type SliceInfo struct {
	name         string
	uplinkMbr    uint64
	downlinkMbr  uint64
	ulBurstBytes uint64
	dlBurstBytes uint64
	ueResList    []UeResource
}

type UeResource struct {
	name string
	dnn  string
}

type upf struct {
	enableUeIPAlloc   bool
	enableEndMarker   bool
	enableFlowMeasure bool
	enableGtpuMonitor bool
	accessIface       string
	coreIface         string
	ippoolCidr        string
	n4addr            string
	accessIP          net.IP
	coreIP            net.IP
	// accessIP6 and coreIP6 are the interfaces' IPv6 GTP-U addresses, when they have
	// one (see IfaceType); the zero Addr otherwise.
	accessIP6 netip.Addr
	coreIP6   netip.Addr
	// n3Family restricts the F-TEIDs the UPF offers on N3 to one family; see
	// IfaceType.TransportFamily.
	n3Family string
	// cpFunctionIntf is the Destination Interface (access or core) a FAR to the
	// CP-function sends through; see CPIfaceInfo.CPFunctionInterface.
	cpFunctionIntf   uint8
	nodeID           localNodeID
	ippool           *IPPool
	peers            []string
	dnn              string
	reportNotifyChan chan uint64
	sliceInfo        *SliceInfo
	readTimeout      time.Duration
	fteidGenerator   *FTEIDGenerator

	datapath
	maxReqRetries uint8
	respTimeout   time.Duration
	enableHBTimer bool
	hbInterval    time.Duration
}

// to be replaced with go-pfcp structs

// Don't change these values.
const (
	tunnelGTPUPort = 2152

	// src-iface consts.
	core   = 0x2
	access = 0x1
	// cpFunction is a PDR whose Source Interface is CP-function: packets the SMF sends
	// (CP2UP, its router advertisements). They arrive in a tunnel to an F-TEID of their
	// own on whichever interface reaches the SMF, so the rule matches any (mask 0), and
	// the datapath never sees this value.
	cpFunction = 0x3

	// far-id specific directions.
	n3 = 0x0
	n6 = 0x1
	n9 = 0x2
)

func (u *upf) isConnected() bool {
	return u.IsConnected(&u.accessIP)
}

func (u *upf) addSliceInfo(sliceInfo *SliceInfo) error {
	if sliceInfo == nil {
		return ErrInvalidArgument("sliceInfo", sliceInfo)
	}

	u.sliceInfo = sliceInfo

	return u.AddSliceInfo(sliceInfo)
}

func fqdnHostname() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}

	// if hostname is already FQDN, return it
	if strings.Contains(hostname, ".") {
		return hostname, nil
	}

	// try to get FQDN via reverse DNS lookup
	addrs, err := net.DefaultResolver.LookupIPAddr(context.Background(), hostname)
	if err != nil {
		logger.PfcpLog.Warnf("failed to get fqdn for %s: %+v", hostname, err)
		return hostname, nil // fallback to short hostname
	}

	for _, addr := range addrs {
		names, err := net.DefaultResolver.LookupAddr(context.Background(), addr.String())
		if err != nil || len(names) == 0 {
			continue
		}

		// return the first FQDN found
		fqdn := strings.TrimSuffix(names[0], ".")
		if strings.Contains(fqdn, ".") {
			return fqdn, nil
		}
	}

	return hostname, nil // fallback to short hostname
}

func NewUPF(conf *Conf, fp datapath) *upf {
	nodeID, err := newLocalNodeID(context.Background(), conf.CPIface,
		net.DefaultResolver.LookupHost, fqdnHostname)
	if err != nil {
		logger.PfcpLog.Fatalln(err)
	}

	u := &upf{
		enableUeIPAlloc:   conf.CPIface.EnableUeIPAlloc,
		enableEndMarker:   conf.EnableEndMarker,
		enableFlowMeasure: conf.EnableFlowMeasure,
		enableGtpuMonitor: conf.EnableGtpuPathMonitoring,
		accessIface:       conf.AccessIface.IfName,
		coreIface:         conf.CoreIface.IfName,
		ippoolCidr:        conf.CPIface.UEIPPool,
		nodeID:            nodeID,
		datapath:          fp,
		dnn:               conf.CPIface.Dnn,
		peers:             conf.CPIface.Peers,
		reportNotifyChan:  make(chan uint64, 1024),
		maxReqRetries:     conf.MaxReqRetries,
		enableHBTimer:     conf.EnableHBTimer,
		readTimeout:       time.Second * time.Duration(conf.ReadTimeout),
		fteidGenerator:    NewFTEIDGenerator(),
		n4addr:            conf.N4Addr,
	}

	if !setupPeersAndInterfaces(u, conf) {
		return nil
	}

	initTimersAndIPPool(u, conf)

	u.SetUpfInfo(u, conf)

	return u
}

func setupPeersAndInterfaces(u *upf, conf *Conf) bool {
	var err error
	if len(conf.CPIface.Peers) > 0 {
		u.peers = make([]string, len(conf.CPIface.Peers))
		nc := copy(u.peers, conf.CPIface.Peers)

		if nc == 0 {
			logger.PfcpLog.Warnln("failed to parse cpiface peers, PFCP Agent will not initiate connection to N4 peers.")
		}
	}

	var accessIP4, coreIP4 netip.Addr

	accessIP4, u.accessIP6, err = resolveTunnelAddrs(conf.AccessIface, tunnelAddrsFromInterface)
	if err != nil {
		logger.PfcpLog.Errorf("failed to get unicast address for access interface %q: %v", conf.AccessIface.IfName, err)
		return false
	}

	coreIP4, u.coreIP6, err = resolveTunnelAddrs(conf.CoreIface, tunnelAddrsFromInterface)
	if err != nil {
		logger.PfcpLog.Errorf("failed to get unicast address for core interface %q: %v", conf.CoreIface.IfName, err)
		return false
	}

	u.accessIP = ipFromAddr(accessIP4)
	u.coreIP = ipFromAddr(coreIP4)
	u.n3Family = conf.AccessIface.TransportFamily

	u.cpFunctionIntf = ie.DstInterfaceAccess
	if conf.CPIface.CPFunctionInterface == cpFunctionViaCore {
		u.cpFunctionIntf = ie.DstInterfaceCore
	}
	logger.PfcpLog.Infof("GTP-U addresses: access %v %v (N3 transport family %q), core %v %v",
		accessIP4, u.accessIP6, u.n3Family, coreIP4, u.coreIP6)

	return true
}

// resolveTunnelAddrs returns an interface's GTP-U addresses: the ones its config names,
// else the interface's own (lookup). transport_family "ipv4" leaves out the IPv6 one, so
// an IPv4-only UPF behaves as one whatever addresses the interface has. An interface
// with neither is an error.
func resolveTunnelAddrs(
	iface IfaceType, lookup func(string) (netip.Addr, netip.Addr, error),
) (v4, v6 netip.Addr, err error) {
	if iface.IPv4 == "" || iface.IPv6 == "" {
		if v4, v6, err = lookup(iface.IfName); err != nil {
			return v4, v6, err
		}
	}

	if iface.IPv4 != "" {
		v4 = netip.MustParseAddr(iface.IPv4) // validateIface checked it
	}

	if iface.IPv6 != "" {
		v6 = netip.MustParseAddr(iface.IPv6)
	}

	if iface.TransportFamily == transportFamilyIPv4 {
		v6 = netip.Addr{}
	}

	if !v4.IsValid() && !v6.IsValid() {
		return v4, v6, ErrNotFoundWithParam("GTP-U address", "interface", iface.IfName)
	}

	return v4, v6, nil
}

// n3Addrs returns the N3 addresses the UPF offers in F-TEIDs it allocates and in its UP
// IP Resource Information: the access interface's, less the family that
// transport_family leaves out.
func (u *upf) n3Addrs() (v4, v6 netip.Addr) {
	v4 = addrFromIP(u.accessIP)
	v6 = u.accessIP6

	switch u.n3Family {
	case transportFamilyIPv4:
		v6 = netip.Addr{}
	case transportFamilyIPv6:
		v4 = netip.Addr{}
	}

	return v4, v6
}

// tunnelIP6Src is the IPv6 address a tunnel through dstIntf is sent from: the access
// interface's for the RAN, the core interface's otherwise. The zero Addr when there is
// none.
func (u *upf) tunnelIP6Src(dstIntf uint8) netip.Addr {
	if dstIntf == ie.DstInterfaceAccess {
		return u.accessIP6
	}

	return u.coreIP6
}

func initTimersAndIPPool(u *upf, conf *Conf) {
	var err error
	u.respTimeout, err = time.ParseDuration(conf.RespTimeout)
	if err != nil {
		logger.PfcpLog.Fatalf("unable to parse resp_timeout %q: %v", conf.RespTimeout, err)
	}

	if u.enableHBTimer {
		if conf.HeartBeatInterval != "" {
			u.hbInterval, err = time.ParseDuration(conf.HeartBeatInterval)
			if err != nil {
				logger.PfcpLog.Fatalf("unable to parse heart_beat_interval %q: %v", conf.HeartBeatInterval, err)
			}
		}
	}

	if u.enableUeIPAlloc {
		u.ippool, err = NewIPPool(u.ippoolCidr)
		if err != nil {
			logger.PfcpLog.Fatalf("ip pool init failed for CIDR %q: %v", u.ippoolCidr, err)
		}
	}
}
