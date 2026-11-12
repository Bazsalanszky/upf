// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Intel Corporation

package pfcpiface

import (
	"fmt"
	"net/netip"

	"github.com/omec-project/upf-epc/logger"
	"github.com/wmnsk/go-pfcp/ie"
)

type operation int

const (
	FwdIEOuterHeaderCreation Bits = 1 << iota
	FwdIEDestinationIntf
	FwdIEPfcpSMReqFlags
)

const (
	ActionForward = 0x2
	ActionDrop    = 0x1
	ActionBuffer  = 0x4
	ActionNotify  = 0x8
)

const (
	create operation = iota
	update
)

type far struct {
	farID   uint32
	fseID   uint64
	fseidIP netip.Addr

	dstIntf uint8
	// cpFunctionVia is the interface (access or core) a FAR whose dstIntf is
	// CP-function sends through (upf.cpFunctionIntf); unused otherwise.
	cpFunctionVia uint8
	sendEndMarker bool
	applyAction   uint8
	tunnelType    uint8
	// tunnelIPSrc is the UPF's address the tunnel is sent from, of tunnelIPDst's family.
	tunnelIPSrc netip.Addr
	// tunnelIPDst is the peer the FAR's Outer Header Creation sends to. When the IE
	// carries both an IPv4 and an IPv6 address the UP function picks one (TS 29.244 clause
	// 8.2.56); this one picks IPv4, unless N3 is restricted to IPv6 (see ohcPeer).
	tunnelIPDst netip.Addr
	tunnelTEID  uint32
	tunnelPort  uint16
}

// egressIntf is the interface the FAR forwards through: its Destination Interface, or for
// CP-function the one configured for it.
func (f far) egressIntf() uint8 {
	if f.dstIntf == ie.DstInterfaceCPFunction {
		return f.cpFunctionVia
	}

	return f.dstIntf
}

func (f far) String() string {
	return fmt.Sprintf("FAR(id=%v, F-SEID=%v, F-SEID IP=%v, dstInterface=%v, tunnelType=%v, "+
		"tunnelIPSrc=%v, tunnelIPDst=%v, tunnelTEID=%v, tunnelSrcPort=%v, "+
		"sendEndMarker=%v, drops=%v, forwards=%v, buffers=%v)", f.farID, f.fseID, f.fseidIP, f.dstIntf,
		f.tunnelType, f.tunnelIPSrc, f.tunnelIPDst, f.tunnelTEID, f.tunnelPort, f.sendEndMarker,
		f.Drops(), f.Forwards(), f.Buffers())
}

func (f *far) Drops() bool {
	return f.applyAction&ActionDrop != 0
}

func (f *far) Buffers() bool {
	return f.applyAction&ActionBuffer != 0
}

func (f *far) Forwards() bool {
	return f.applyAction&ActionForward != 0
}

func (f *far) parseFAR(farIE *ie.IE, fseid uint64, upf *upf, op operation) error {
	f.fseID = fseid

	fwdIEs, err := f.parseFARBasicFields(farIE, op)
	if err != nil {
		return err
	}

	f.sendEndMarker = false

	var fields Bits
	var ohcFields *ie.OuterHeaderCreationFields

	var ohcV4, ohcV6 netip.Addr

	for _, fwdIE := range fwdIEs {
		switch fwdIE.Type {
		case ie.OuterHeaderCreation:
			fields = Set(fields, FwdIEOuterHeaderCreation)

			ohcFields, err = fwdIE.OuterHeaderCreation()
			if err != nil {
				logger.PfcpLog.Errorln("unable to parse OuterHeaderCreationFields")
				continue
			}

			f.tunnelTEID = ohcFields.TEID
			ohcV4 = addrFromIP(ohcFields.IPv4Address)
			ohcV6 = addrFromIP(ohcFields.IPv6Address)

			f.tunnelType = uint8(1) // Preserve the existing tunnel type encoding for GTP-U forwarding.
			f.tunnelPort = tunnelGTPUPort
		case ie.DestinationInterface:
			fields = Set(fields, FwdIEDestinationIntf)

			f.dstIntf, err = fwdIE.DestinationInterface()
			if err != nil {
				logger.PfcpLog.Errorln("unable to parse DestinationInterface field")
				continue
			}

			switch f.dstIntf {
			case ie.DstInterfaceAccess:
				f.tunnelIPSrc = addrFromIP(upf.accessIP)
			case ie.DstInterfaceCore:
				f.tunnelIPSrc = addrFromIP(upf.coreIP)
			case ie.DstInterfaceCPFunction:
				// To the SMF's GTP-U endpoint (UP2CP: a UE's router solicitation),
				// through the configured interface and from its address.
				f.cpFunctionVia = upf.cpFunctionIntf
				f.tunnelIPSrc = addrFromIP(upf.accessIP)
				if f.cpFunctionVia == ie.DstInterfaceCore {
					f.tunnelIPSrc = addrFromIP(upf.coreIP)
				}
			}
		case ie.PFCPSMReqFlags:
			fields = Set(fields, FwdIEPfcpSMReqFlags)

			smReqFlags, err := fwdIE.PFCPSMReqFlags()
			if err != nil {
				logger.PfcpLog.Errorln("unable to parse PFCPSMReqFlags")
				continue
			}

			if has2ndBit(smReqFlags) {
				f.sendEndMarker = true
			}
		}
	}

	if ohcV4.IsValid() || ohcV6.IsValid() {
		f.tunnelIPDst = ohcPeer(ohcV4, ohcV6, upf.n3Family)
		if f.tunnelIPDst.Is6() {
			// The IPv6 source is the interface's; the datapath sends from it whatever
			// the FAR says (GtpuEncap's access_ip6/core_ip6), and the FAR keeps it for
			// the end marker it may send.
			f.tunnelIPSrc = upf.tunnelIP6Src(f.egressIntf())
		}
	}

	return f.checkDatapathSupport()
}

// ohcPeer picks the peer of an Outer Header Creation: the address it gives, or, when it
// gives both, IPv4 -- which the UPF sent to before it had IPv6 N3 -- unless N3 is
// restricted to IPv6.
func ohcPeer(v4, v6 netip.Addr, n3Family string) netip.Addr {
	if !v4.IsValid() || (v6.IsValid() && n3Family == transportFamilyIPv6) {
		return v6
	}

	return v4
}

// checkDatapathSupport refuses a FAR whose tunnel the datapath cannot build: one to an
// IPv6 peer through an interface with no IPv6 address to send from. See
// pdr.checkDatapathSupport for why here.
func (f far) checkDatapathSupport() error {
	if f.tunnelIPDst.Is6() && !f.tunnelIPSrc.IsValid() {
		return ErrUnsupported("FAR creating an IPv6 outer header (no IPv6 address on the interface) to",
			f.tunnelIPDst)
	}

	return nil
}

func (f *far) parseFARBasicFields(farIE *ie.IE, op operation) ([]*ie.IE, error) {
	farID, err := farIE.FARID()
	if err != nil {
		return nil, err
	}

	f.farID = farID

	action, err := farIE.ApplyAction()
	if err != nil {
		return nil, err
	}

	if action[0] == 0 {
		return nil, ErrInvalidArgument("FAR Action", action)
	}

	f.applyAction = action[0]

	var fwdIEs []*ie.IE

	switch op {
	case create:
		if (f.applyAction & ActionForward) != 0 {
			fwdIEs, err = farIE.ForwardingParameters()
			if err != nil {
				return nil, err
			}
		}
	case update:
		if (f.applyAction & ActionForward) != 0 {
			fwdIEs, err = farIE.UpdateForwardingParameters()
			if err != nil {
				return nil, err
			}
		}
	default:
		return nil, ErrInvalidOperation(op)
	}

	return fwdIEs, nil
}
