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

	dstIntf       uint8
	sendEndMarker bool
	applyAction   uint8
	tunnelType    uint8
	tunnelIPSrc   netip.Addr
	tunnelIPDst   netip.Addr
	tunnelTEID    uint32
	tunnelPort    uint16
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
			f.tunnelIPDst = addrFromIP(ohcFields.IPv4Address)
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
