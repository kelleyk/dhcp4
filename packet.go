// IPv4 DHCP Library for Parsing and Creating DHCP Packets, along with basic DHCP server functionality
//
// Author: http://richard.warburton.it/
//
// Copyright: 2014 Skagerrak Software - http://www.skagerraksoftware.com/
package dhcp4

import (
	"net"
	"time"
)

type Option struct {
	Code  OptionCode
	Value []byte
}
type OptionCode byte
type OpCode byte
type MessageType byte // Option 53

// A DHCP packet
type Packet []byte

func (p Packet) OpCode() OpCode { return OpCode(p[0]) }
func (p Packet) HType() byte    { return p[1] }
func (p Packet) HLen() byte     { return p[2] }
func (p Packet) Hops() byte     { return p[3] }
func (p Packet) XId() []byte    { return p[4:8] }
func (p Packet) Secs() []byte   { return p[8:10] } // Never Used?
func (p Packet) Flags() []byte  { return p[10:12] }
func (p Packet) CIAddr() net.IP { return net.IP(p[12:16]) }
func (p Packet) YIAddr() net.IP { return net.IP(p[16:20]) }
func (p Packet) SIAddr() net.IP { return net.IP(p[20:24]) }
func (p Packet) GIAddr() net.IP { return net.IP(p[24:28]) }
func (p Packet) CHAddr() net.HardwareAddr {
	hLen := p.HLen()
	if hLen > 16 { // Prevent chaddr exceeding p boundary
		hLen = 16
	}
	return net.HardwareAddr(p[28 : 28+hLen]) // max endPos 44
}

// 192 bytes of zeros BOOTP legacy

// BOOTP legacy
func (p Packet) SName() []byte { return trimNull(p[44:108]) }

// BOOTP legacy
func (p Packet) File() []byte { return trimNull(p[108:236]) }

func trimNull(d []byte) []byte {
	for i, v := range d {
		if v == 0 {
			return d[:i]
		}
	}
	return d
}

func (p Packet) Cookie() []byte { return p[236:240] }
func (p Packet) Options() []byte {
	if len(p) > 240 {
		return p[240:]
	}
	return nil
}

func (p Packet) Broadcast() bool { return p.Flags()[0] > 127 }

func (p Packet) SetBroadcast(broadcast bool) {
	if p.Broadcast() != broadcast {
		p.Flags()[0] ^= 128
	}
}

func (p Packet) SetOpCode(c OpCode) { p[0] = byte(c) }
func (p Packet) SetCHAddr(a net.HardwareAddr) {
	copy(p[28:44], a)
	p[2] = byte(len(a))
}
func (p Packet) SetHType(hType byte)     { p[1] = hType }
func (p Packet) SetCookie(cookie []byte) { copy(p.Cookie(), cookie) }
func (p Packet) SetHops(hops byte)       { p[3] = hops }
func (p Packet) SetXId(xId []byte)       { copy(p.XId(), xId) }
func (p Packet) SetSecs(secs []byte)     { copy(p.Secs(), secs) }
func (p Packet) SetFlags(flags []byte)   { copy(p.Flags(), flags) }
func (p Packet) SetCIAddr(ip net.IP)     { copy(p.CIAddr(), ip.To4()) }
func (p Packet) SetYIAddr(ip net.IP)     { copy(p.YIAddr(), ip.To4()) }
func (p Packet) SetSIAddr(ip net.IP)     { copy(p.SIAddr(), ip.To4()) }
func (p Packet) SetGIAddr(ip net.IP)     { copy(p.GIAddr(), ip.To4()) }

// BOOTP legacy
func (p Packet) SetSName(sName []byte) {
	copy(p[44:108], sName)
	if len(sName) < 64 {
		p[44+len(sName)] = 0
	}
}

// BOOTP legacy
func (p Packet) SetFile(file []byte) {
	copy(p[108:236], file)
	if len(file) < 128 {
		p[108+len(file)] = 0
	}
}

// Map of DHCP options
type Options map[OptionCode][]byte

// Parses the packet's options into an Options map
func (p Packet) ParseOptions() Options {
	opts := p.Options()
	options := make(Options, 10)
	for len(opts) >= 2 && OptionCode(opts[0]) != End {
		if OptionCode(opts[0]) == Pad {
			opts = opts[1:]
			continue
		}
		size := int(opts[1])
		if len(opts) < 2+size {
			break
		}
		options[OptionCode(opts[0])] = opts[2 : 2+size]
		opts = opts[2+size:]
	}
	return options
}

func NewPacket(opCode OpCode) Packet {
	p := make(Packet, 241)
	p.SetOpCode(opCode)
	p.SetHType(1) // Ethernet
	p.SetCookie([]byte{99, 130, 83, 99})
	p[240] = byte(End)
	return p
}

// Appends a DHCP option to the end of a packet
func (p *Packet) AddOption(o OptionCode, value []byte) {
	*p = append((*p)[:len(*p)-1], []byte{byte(o), byte(len(value))}...) // Strip off End, Add OptionCode and Length
	*p = append(*p, value...)                                           // Add Option Value
	*p = append(*p, byte(End))                                          // Add on new End
}

// Removes all options from packet.
func (p *Packet) StripOptions() {
	*p = append((*p)[:240], byte(End))
}

// Creates a request packet that a Client would send to a server.
func RequestPacket(mt MessageType, chAddr net.HardwareAddr, cIAddr net.IP, xId []byte, broadcast bool, options []Option) Packet {
	p := NewPacket(BootRequest)
	p.SetCHAddr(chAddr)
	p.SetXId(xId)
	if cIAddr != nil {
		p.SetCIAddr(cIAddr)
	}
	p.SetBroadcast(broadcast)
	p.AddOption(OptionDHCPMessageType, []byte{byte(mt)})
	for _, o := range options {
		p.AddOption(o.Code, o.Value)
	}
	p.PadToMinSize()
	return p
}

// ReplyPacket creates a reply packet that a Server would send to a client.
// It uses the req Packet param to copy across common/necessary fields to
// associate the reply the request.
func ReplyPacket(req Packet, mt MessageType, serverId, yIAddr net.IP, leaseDuration time.Duration, options []Option) Packet {
	p := NewPacket(BootReply)
	p.SetXId(req.XId())
	p.SetFlags(req.Flags())
	p.SetYIAddr(yIAddr)
	p.SetGIAddr(req.GIAddr())
	p.SetCHAddr(req.CHAddr())
	p.AddOption(OptionDHCPMessageType, []byte{byte(mt)})
	p.AddOption(OptionServerIdentifier, []byte(serverId))
	p.AddOption(OptionIPAddressLeaseTime, OptionsLeaseTime(leaseDuration))
	for _, o := range options {
		p.AddOption(o.Code, o.Value)
	}
	p.PadToMinSize()
	return p
}

// PadToMinSize pads a packet so that when sent over UDP, the entire packet,
// is 300 bytes (BOOTP min), to be compatible with really old devices.
var padder [272]byte

func (p *Packet) PadToMinSize() {
	if n := len(*p); n < 272 {
		*p = append(*p, padder[:272-n]...)
	}
}

// N.B.: All of these constants are described here: https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml

// OpCodes
const (
	BootRequest OpCode = 1 // From Client
	BootReply   OpCode = 2 // From Server
)

//go:generate stringer -type=MessageType

// DHCP Message Type 53
const (
	Discover         MessageType = 1 // Broadcast Packet From Client - Can I have an IP?
	Offer                        = 2 // Broadcast From Server - Here's an IP
	Request                      = 3 // Broadcast From Client - I'll take that IP (Also start for renewals)
	Decline                      = 4 // Broadcast From Client - Sorry I can't use that IP
	ACK                          = 5 // From Server, Yes you can have that IP
	NAK                          = 6 // From Server, No you cannot have that IP
	Release                      = 7 // From Client, I don't need that IP anymore
	Inform                       = 8 // From Client, I have this IP and there's nothing you can do about it
	ForceRenew                   = 9
	LeaseQuery                   = 10
	LeaseUnassigned              = 11
	LeaseUnknown                 = 12
	LeaseActive                  = 13
	BulkLeaseQuery               = 14
	LeaseQueryDone               = 15
	ActiveLeaseQuery             = 16
	LeaseQueryStatus             = 17
	TLS                          = 18
)

//go:generate stringer -type=OptionCode

// DHCP Options
const (
	End                          OptionCode = 255
	Pad                                     = 0
	OptionSubnetMask                        = 1
	OptionTimeOffset                        = 2
	OptionRouter                            = 3
	OptionTimeServer                        = 4
	OptionNameServer                        = 5
	OptionDomainNameServer                  = 6
	OptionLogServer                         = 7
	OptionCookieServer                      = 8
	OptionLPRServer                         = 9
	OptionImpressServer                     = 10
	OptionResourceLocationServer            = 11
	OptionHostName                          = 12
	OptionBootFileSize                      = 13
	OptionMeritDumpFile                     = 14
	OptionDomainName                        = 15
	OptionSwapServer                        = 16
	OptionRootPath                          = 17
	OptionExtensionsPath                    = 18

	// IP Layer Parameters per Host
	OptionIPForwardingEnableDisable          = 19
	OptionNonLocalSourceRoutingEnableDisable = 20
	OptionPolicyFilter                       = 21
	OptionMaximumDatagramReassemblySize      = 22
	OptionDefaultIPTimeToLive                = 23
	OptionPathMTUAgingTimeout                = 24
	OptionPathMTUPlateauTable                = 25

	// IP Layer Parameters per Interface
	OptionInterfaceMTU              = 26
	OptionAllSubnetsAreLocal        = 27
	OptionBroadcastAddress          = 28
	OptionPerformMaskDiscovery      = 29
	OptionMaskSupplier              = 30
	OptionPerformRouterDiscovery    = 31
	OptionRouterSolicitationAddress = 32
	OptionStaticRoute               = 33

	// Link Layer Parameters per Interface
	OptionTrailerEncapsulation  = 34
	OptionARPCacheTimeout       = 35
	OptionEthernetEncapsulation = 36

	// TCP Parameters
	OptionTCPDefaultTTL        = 37
	OptionTCPKeepaliveInterval = 38
	OptionTCPKeepaliveGarbage  = 39

	// Application and Service Parameters
	OptionNetworkInformationServiceDomain            = 40
	OptionNetworkInformationServers                  = 41
	OptionNetworkTimeProtocolServers                 = 42
	OptionVendorSpecificInformation                  = 43
	OptionNetBIOSOverTCPIPNameServer                 = 44
	OptionNetBIOSOverTCPIPDatagramDistributionServer = 45
	OptionNetBIOSOverTCPIPNodeType                   = 46
	OptionNetBIOSOverTCPIPScope                      = 47
	OptionXWindowSystemFontServer                    = 48
	OptionXWindowSystemDisplayManager                = 49
	OptionNetworkInformationServicePlusDomain        = 64
	OptionNetworkInformationServicePlusServers       = 65
	OptionMobileIPHomeAgent                          = 68
	OptionSimpleMailTransportProtocol                = 69
	OptionPostOfficeProtocolServer                   = 70
	OptionNetworkNewsTransportProtocol               = 71
	OptionDefaultWorldWideWebServer                  = 72
	OptionDefaultFingerServer                        = 73
	OptionDefaultInternetRelayChatServer             = 74
	OptionStreetTalkServer                           = 75
	OptionStreetTalkDirectoryAssistance              = 76

	OptionRelayAgentInformation = 82

	// DHCP Extensions
	OptionRequestedIPAddress     = 50
	OptionIPAddressLeaseTime     = 51
	OptionOverload               = 52
	OptionDHCPMessageType        = 53
	OptionServerIdentifier       = 54
	OptionParameterRequestList   = 55
	OptionMessage                = 56
	OptionMaximumDHCPMessageSize = 57
	OptionRenewalTimeValue       = 58
	OptionRebindingTimeValue     = 59
	OptionVendorClassIdentifier  = 60
	OptionClientIdentifier       = 61

	OptionTFTPServerName = 66
	OptionBootFileName   = 67

	OptionUserClass = 77

	OptionClientArchitecture = 93

	OptionTZPOSIXString    = 100
	OptionTZDatabaseString = 101

	OptionClasslessRouteFormat = 121

	OptionNetWareIPDomain = 62
	OptionNetWareIPOption = 63 // see sub-option codes specified in RFC2242

	OptionDirectoryAgent = 78
	OptionServiceScope   = 79
	OptionRapidCommit    = 80
	OptionClientFQDN     = 81

	OptioniSNS = 83 // Internet Storage Name Service

	OptionNDSServers                    = 85 // Novell Directory Services
	OptionNDSTreeName                   = 86
	OptionNDSContext                    = 87
	OptionBCMCSControllerDomainNameList = 88
	OptionBCMCSControllerIPv4Address    = 89
	OptionAuthentication                = 90
	OptionClientLastTransactionTime     = 91
	OptionAssociatedIP                  = 92

	OptionClientNDI = 94
	OptionLDAP      = 95

	OptionUUID         = 97
	OptionUserAuth     = 98 // Open Group's User Authentication
	OptionGeoconfCivic = 99
)

/* Notes
A DHCP server always returns its own address in the 'server identifier' option.
DHCP defines a new 'client identifier' option that is used to pass an explicit client identifier to a DHCP server.
*/
