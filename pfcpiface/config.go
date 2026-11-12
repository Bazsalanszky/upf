// SPDX-License-Identifier: Apache-2.0
// Copyright 2022-present Open Networking Foundation

package pfcpiface

import (
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	// Default values
	maxReqRetriesDefault = 5
	respTimeoutDefault   = 2 * time.Second
	hbIntervalDefault    = 5 * time.Second
	readTimeoutDefault   = 15 * time.Second
)

// Conf : Json conf struct.
type Conf struct {
	Mode                     string           `json:"mode"`
	AccessIface              IfaceType        `json:"access"`
	CoreIface                IfaceType        `json:"core"`
	CPIface                  CPIfaceInfo      `json:"cpiface"`
	EnableGtpuPathMonitoring bool             `json:"enable_gtpu_path_monitoring"`
	EnableFlowMeasure        bool             `json:"measure_flow"`
	SimInfo                  SimModeInfo      `json:"sim"`
	ConnTimeout              uint32           `json:"conn_timeout"` // TODO(max): unused, remove
	ReadTimeout              uint32           `json:"read_timeout"` // TODO(max): convert to duration string
	EnableNotifyBess         bool             `json:"enable_notify_bess"`
	EnableEndMarker          bool             `json:"enable_end_marker"`
	NotifySockAddr           string           `json:"notify_sockaddr"`
	EndMarkerSockAddr        string           `json:"endmarker_sockaddr"`
	LogLevel                 zapcore.Level    `json:"log_level"`
	QciQosConfig             []QciQosConfig   `json:"qci_qos_config"`
	SliceMeterConfig         SliceMeterConfig `json:"slice_rate_limit_config"`
	MaxReqRetries            uint8            `json:"max_req_retries"`
	RespTimeout              string           `json:"resp_timeout"`
	EnableHBTimer            bool             `json:"enable_hbTimer"`
	HeartBeatInterval        string           `json:"heart_beat_interval"`
	N4Addr                   string           `json:"n4_addr"`
}

// QciQosConfig : Qos configured attributes.
type QciQosConfig struct {
	QCI                uint8  `json:"qci"`
	CBS                uint32 `json:"cbs"`
	PBS                uint32 `json:"pbs"`
	EBS                uint32 `json:"ebs"`
	BurstDurationMs    uint32 `json:"burst_duration_ms"`
	SchedulingPriority uint32 `json:"priority"`
}

type SliceMeterConfig struct {
	N6RateBps    uint64 `json:"n6_bps"`
	N6BurstBytes uint64 `json:"n6_burst_bytes"`
	N3RateBps    uint64 `json:"n3_bps"`
	N3BurstBytes uint64 `json:"n3_burst_bytes"`
}

// SimModeInfo : Sim mode attributes.
type SimModeInfo struct {
	MaxSessions uint32 `json:"max_sessions"`
	StartUEIP   net.IP `json:"start_ue_ip"`
	StartENBIP  net.IP `json:"start_enb_ip"`
	StartAUPFIP net.IP `json:"start_aupf_ip"`
	N6AppIP     net.IP `json:"n6_app_ip"`
	N9AppIP     net.IP `json:"n9_app_ip"`
	StartN3TEID string `json:"start_n3_teid"`
	StartN9TEID string `json:"start_n9_teid"`
	UplinkMBR   uint64 `json:"uplink_mbr"`
	DownlinkMBR uint64 `json:"downlink_mbr"`
	UplinkGBR   uint64 `json:"uplink_gbr"`
	DownlinkGBR uint64 `json:"downlink_gbr"`
}

// CPIfaceInfo : CPIface interface settings.
type CPIfaceInfo struct {
	Peers           []string `json:"peers"`
	UseFQDN         bool     `json:"use_fqdn"`
	NodeID          string   `json:"hostname"`
	HTTPPort        string   `json:"http_port"`
	Dnn             string   `json:"dnn"`
	EnableUeIPAlloc bool     `json:"enable_ue_ip_alloc"`
	UEIPPool        string   `json:"ue_ip_pool"`

	// AdvertisedNodeID (node_id) is the Node ID to advertise as it is: an IPv4 or IPv6
	// literal, or an FQDN. It takes precedence over NodeID (hostname), which is a name
	// that is resolved, and over UseFQDN.
	AdvertisedNodeID string `json:"node_id"`

	// CPFunctionInterface (cp_function_interface) is the interface a FAR whose
	// Destination Interface is CP-function sends through: "access" (the default) or
	// "core". Such a FAR tunnels a UE's packets to the SMF's GTP-U endpoint -- the
	// router solicitations of an IPv6 PDU session (TS 23.501 clause 5.8.2.2.3,
	// TS 29.244 clause 5.2.1) -- and the endpoint has to be reachable from it.
	CPFunctionInterface string `json:"cp_function_interface"`
}

// Values of CPIfaceInfo.CPFunctionInterface.
const (
	cpFunctionViaAccess = "access"
	cpFunctionViaCore   = "core"
)

// IfaceType : Gateway interface struct.
//
// The N3 (access) and N9 (core) addresses are the interface's own: its first IPv4
// address and its first global IPv6 address. IPv4 and IPv6 name them explicitly, for an
// interface with more than one. TransportFamily restricts the GTP-U tunnels the UPF
// offers on it to one family ("ipv4" or "ipv6"); empty offers every family the
// interface has an address of. The same keys configure the BESS pipeline (up4.bess).
type IfaceType struct {
	IfName          string `json:"ifname"`
	IPv4            string `json:"ipv4"`
	IPv6            string `json:"ipv6"`
	TransportFamily string `json:"transport_family"`
}

// Values of IfaceType.TransportFamily.
const (
	transportFamilyAny  = ""
	transportFamilyIPv4 = "ipv4"
	transportFamilyIPv6 = "ipv6"
)

// validateIface checks the address keys of an interface.
func validateIface(name string, iface IfaceType) error {
	switch iface.TransportFamily {
	case transportFamilyAny, transportFamilyIPv4, transportFamilyIPv6:
	default:
		return ErrInvalidArgumentWithReason("conf."+name+".transport_family", iface.TransportFamily,
			`not "ipv4", "ipv6" or empty`)
	}

	if iface.IPv4 != "" {
		if a, err := netip.ParseAddr(iface.IPv4); err != nil || !a.Is4() {
			return ErrInvalidArgumentWithReason("conf."+name+".ipv4", iface.IPv4, "not an IPv4 address")
		}
	}

	if iface.IPv6 != "" {
		if a, err := netip.ParseAddr(iface.IPv6); err != nil || !a.Is6() || a.Is4In6() || !a.IsGlobalUnicast() {
			return ErrInvalidArgumentWithReason("conf."+name+".ipv6", iface.IPv6, "not a global IPv6 address")
		}
	}

	return nil
}

// validateConf checks that the given config reaches a baseline of correctness.
func validateConf(conf Conf) error {
	// Mode is only relevant in a BESS deployment.
	validModes := map[string]struct{}{
		"af_xdp":    {},
		"af_packet": {},
		"dpdk":      {},
		"sim":       {},
	}
	if _, ok := validModes[conf.Mode]; !ok {
		return ErrInvalidArgumentWithReason("conf.Mode", conf.Mode, "invalid mode")
	}

	if err := validateUEIPPoolAndPeers(conf); err != nil {
		return err
	}
	if err := validateN4Addresses(conf); err != nil {
		return err
	}
	if err := validateIface("access", conf.AccessIface); err != nil {
		return err
	}
	if err := validateIface("core", conf.CoreIface); err != nil {
		return err
	}
	switch conf.CPIface.CPFunctionInterface {
	case "", cpFunctionViaAccess, cpFunctionViaCore:
	default:
		return ErrInvalidArgumentWithReason("conf.cpiface.cp_function_interface",
			conf.CPIface.CPFunctionInterface, `not "access", "core" or empty`)
	}
	if err := validateTimeouts(conf); err != nil {
		return err
	}

	return nil
}

func validateUEIPPoolAndPeers(conf Conf) error {
	if conf.CPIface.EnableUeIPAlloc {
		_, _, err := net.ParseCIDR(conf.CPIface.UEIPPool)
		if err != nil {
			return ErrInvalidArgumentWithReason("conf.UEIPPool", conf.CPIface.UEIPPool, err.Error())
		}
	}

	for _, peer := range conf.CPIface.Peers {
		ip := net.ParseIP(peer)
		if ip == nil {
			return ErrInvalidArgumentWithReason("conf.CPIface.Peers", peer, "invalid IP")
		}
	}
	return nil
}

// validateN4Addresses checks n4_addr and cpiface.node_id. Both take an IPv6 literal
// without brackets or port, as cpiface.peers does; a bracketed one or a host:port used
// to fail only once the agent tried to listen, as a fatal error.
func validateN4Addresses(conf Conf) error {
	if a := conf.N4Addr; a != "" {
		// An IP literal (with a zone, for a link-local address), or a host name.
		if _, err := netip.ParseAddr(a); err != nil && strings.ContainsAny(a, ":[]") {
			return ErrInvalidArgumentWithReason("conf.N4Addr", a,
				"not an IP address or host name (an IPv6 address is written without brackets or port)")
		}
	}

	if id := conf.CPIface.AdvertisedNodeID; id != "" {
		if a, err := netip.ParseAddr(id); err == nil {
			if a.Zone() != "" {
				return ErrInvalidArgumentWithReason("conf.CPIface.AdvertisedNodeID", id,
					"a Node ID address has no zone")
			}
		} else if !isNodeIDFQDN(id) {
			return ErrInvalidArgumentWithReason("conf.CPIface.AdvertisedNodeID", id,
				"neither an IP address nor an FQDN (an IPv6 address is written without brackets)")
		}
	}

	return nil
}

// isNodeIDFQDN reports whether s can be sent as an FQDN Node ID: dot-separated labels
// of 1 to 63 octets, 255 octets at most, nothing that belongs to an address. A trailing
// dot is allowed; the root label is not encoded.
func isNodeIDFQDN(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 || strings.ContainsAny(s, ":[]/%@ \t") {
		return false
	}

	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 {
			return false
		}
	}

	return true
}

func validateTimeouts(conf Conf) error {
	if _, err := time.ParseDuration(conf.RespTimeout); err != nil {
		return ErrInvalidArgumentWithReason("conf.RespTimeout", conf.RespTimeout, "invalid duration")
	}

	if conf.ReadTimeout == 0 {
		return ErrInvalidArgumentWithReason("conf.ReadTimeout", conf.ReadTimeout, "invalid duration")
	}

	if conf.MaxReqRetries == 0 {
		return ErrInvalidArgumentWithReason("conf.MaxReqRetries", conf.MaxReqRetries, "invalid number of retries")
	}

	if conf.EnableHBTimer {
		if _, err := time.ParseDuration(conf.HeartBeatInterval); err != nil {
			return err
		}
	}
	return nil
}

// removeComments strips // line comments and /* */ block comments from a JSONC
// document, leaving comment markers that appear inside string literals alone.
//
// That last part is the whole point: a regex sweep for `//.*$` also matches a "//"
// inside a string value -- the scheme of a URL, or a path with a doubled separator --
// and drops the rest of the line. The bess-upf chart renders this file on one line
// (toJson), so the rest of the file goes with it, and the parse fails as "unexpected
// end of JSON input" with nothing to say which value was to blame.
//
// An unterminated block comment is left in place for the parser to report, rather
// than swallowing the rest of the document.
func removeComments(jsonc string) string {
	var b strings.Builder

	b.Grow(len(jsonc))

	inString, escaped := false, false

	for i := 0; i < len(jsonc); i++ {
		c := jsonc[i]

		if inString {
			b.WriteByte(c)

			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}

			continue
		}

		switch {
		case c == '"':
			inString = true

			b.WriteByte(c)
		case c == '/' && i+1 < len(jsonc) && jsonc[i+1] == '/':
			// Line comment: drop it up to the newline, which stays, as it did with the regex.
			for i < len(jsonc) && jsonc[i] != '\n' {
				i++
			}

			if i < len(jsonc) {
				b.WriteByte('\n')
			}
		case c == '/' && i+1 < len(jsonc) && jsonc[i+1] == '*':
			end := strings.Index(jsonc[i+2:], "*/")
			if end < 0 {
				b.WriteString(jsonc[i:])

				return b.String()
			}

			i += 2 + end + 1 // the loop's own i++ steps past the closing '/'
		default:
			b.WriteByte(c)
		}
	}

	return b.String()
}

// LoadConfigFile : parse jsonc file and populate corresponding struct
func LoadConfigFile(filepath string) (Conf, error) {
	// Open up file.
	jsoncFile, err := os.ReadFile(filepath)
	if err != nil {
		return Conf{}, err
	}

	jsonData := removeComments(string(jsoncFile))

	var conf Conf
	conf.LogLevel = zap.InfoLevel

	err = json.Unmarshal([]byte(jsonData), &conf)
	if err != nil {
		return Conf{}, err
	}

	// Set defaults, when missing.
	if conf.RespTimeout == "" {
		conf.RespTimeout = respTimeoutDefault.String()
	}

	if conf.ReadTimeout == 0 {
		conf.ReadTimeout = uint32(readTimeoutDefault.Seconds())
	}

	if conf.MaxReqRetries == 0 {
		conf.MaxReqRetries = maxReqRetriesDefault
	}

	if conf.EnableHBTimer {
		if conf.HeartBeatInterval == "" {
			conf.HeartBeatInterval = hbIntervalDefault.String()
		}
	}

	// Perform basic validation.
	err = validateConf(conf)
	if err != nil {
		return Conf{}, err
	}

	return conf, nil
}
