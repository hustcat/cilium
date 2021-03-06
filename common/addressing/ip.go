//
// Copyright 2016 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
package addressing

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"

	"github.com/cilium/cilium/common/ipam"
)

type CiliumIP interface {
	NodeID() uint32
	State() uint16
	EndpointID() uint16
	IPNet(ones int) *net.IPNet
	String() string
}

type CiliumIPv6 []byte

// - Be an IPv6 address
// - Node ID, bits from 112 to 120, must be different than 0
// - Endpoint ID, bits from 120 to 128, must be equal to 0
func NewCiliumIPv6(address string) (CiliumIPv6, error) {
	ip := net.ParseIP(address)
	if ip == nil {
		return nil, fmt.Errorf("Unable to parse IPv6 address: %s", address)
	}

	if ip16 := ip.To16(); ip16 == nil {
		return nil, fmt.Errorf("Not an IPv6 address")
	} else {
		return DeriveCiliumIPv6(ip16), nil
	}
}

func DeriveCiliumIPv6(src net.IP) CiliumIPv6 {
	ip := make(CiliumIPv6, 16)
	copy(ip, src.To16())
	return ip
}

// Returns the node ID portion of the address or 0
func (ip CiliumIPv6) NodeID() uint32 {
	return binary.BigEndian.Uint32(ip[8:12])
}

func (ip CiliumIPv6) State() uint16 {
	return binary.BigEndian.Uint16(ip[12:14])
}

// Returns the container ID portion of the address or 0
func (ip CiliumIPv6) EndpointID() uint16 {
	return binary.BigEndian.Uint16(ip[14:])
}

// Returns true if IP is a valid IP for a container
// To be valid must obey to the following rules:
// - Node ID, bits from 64 to 96, must be different than 0
// - State, bits from 96 to 112, must be 0
// - Endpoint ID, bits from 112 to 128, must be different than 0
func (ip CiliumIPv6) ValidContainerIP() bool {
	return ip.NodeID() != 0 && ip.State() == 0 && ip.EndpointID() != 0
}

// Returns true if IP is a valid IP of a node
// - Node ID, bits from 64 to 96, must be different than 0
// - State, bits from 96 to 112, must be 0
// - Endpoint ID, bits from 112 to 128, must be 0
func (ip *CiliumIPv6) ValidNodeIP() bool {
	return ip.NodeID() != 0 && ip.State() == 0 && ip.EndpointID() == 0
}

// NodeIP() return the node's IP based on an endpoint IP
// of the local node
func (ip CiliumIPv6) NodeIP() net.IP {
	nodeAddr := make(net.IP, len(ip))
	copy(nodeAddr, ip)
	nodeAddr[14] = 0
	nodeAddr[15] = 0
	return nodeAddr
}

// Returns the host address from the node ID
func (ip CiliumIPv6) HostIP() net.IP {
	nodeAddr := make(net.IP, len(ip))
	copy(nodeAddr, ip)
	nodeAddr[14] = 0xff
	nodeAddr[15] = 0xff
	return nodeAddr
}

func (ip CiliumIPv6) IPNet(ones int) *net.IPNet {
	return &net.IPNet{
		IP:   ip.IP(),
		Mask: net.CIDRMask(ones, 128),
	}
}

func (ip CiliumIPv6) IP() net.IP {
	return net.IP(ip)
}

func (ip CiliumIPv6) IPAMReq() ipam.IPAMReq {
	i := ip.IP()
	return ipam.IPAMReq{IP: &i}
}

func (ip CiliumIPv6) String() string {
	if ip == nil {
		return ""
	}

	return net.IP(ip).String()
}

func (ip CiliumIPv6) MarshalJSON() ([]byte, error) {
	return json.Marshal(net.IP(ip))
}

func (ip *CiliumIPv6) UnmarshalJSON(b []byte) error {
	if len(b) < len(`""`) {
		return fmt.Errorf("Invalid CiliumIPv6 '%s'", string(b))
	}

	str := string(b[1 : len(b)-1])
	if str == "" {
		return nil
	}

	c, err := NewCiliumIPv6(str)
	if err != nil {
		return fmt.Errorf("Invalid CiliumIPv6 '%s': %s", str, err)
	}

	*ip = c
	return nil
}

type CiliumIPv4 []byte

func NewCiliumIPv4(address string) (CiliumIPv4, error) {
	ip := net.ParseIP(address)
	if ip == nil {
		return nil, fmt.Errorf("Unable to parse IPv4 address: %s", address)
	}

	if ip4 := ip.To4(); ip4 == nil {
		return nil, fmt.Errorf("Not an IPv4 address")
	} else {
		return DeriveCiliumIPv4(ip4), nil
	}
}

func DeriveCiliumIPv4(src net.IP) CiliumIPv4 {
	ip := make(CiliumIPv4, 4)
	copy(ip, src.To4())
	return ip
}

func (ip CiliumIPv4) NodeID() uint32 {
	data := make([]byte, 4)
	copy(data, ip[0:2])
	return binary.BigEndian.Uint32(data)
}

func (ip CiliumIPv4) EndpointID() uint16 {
	return binary.BigEndian.Uint16(ip[2:])
}

func (ip CiliumIPv4) IPNet(ones int) *net.IPNet {
	return &net.IPNet{
		IP:   net.IP(ip),
		Mask: net.CIDRMask(ones, 32),
	}
}

func (ip CiliumIPv4) IP() net.IP {
	return net.IP(ip)
}

func (ip CiliumIPv4) IPAMReq() ipam.IPAMReq {
	i := ip.IP()
	return ipam.IPAMReq{IP: &i}
}

func (ip CiliumIPv4) String() string {
	if ip == nil {
		return ""
	}

	return net.IP(ip).String()
}

func (ip CiliumIPv4) MarshalJSON() ([]byte, error) {
	return json.Marshal(net.IP(ip))
}

func (ip *CiliumIPv4) UnmarshalJSON(b []byte) error {
	if len(b) < len(`""`) {
		return fmt.Errorf("Invalid CiliumIPv4 '%s'", string(b))
	}

	str := string(b[1 : len(b)-1])
	if str == "" {
		return nil
	}

	c, err := NewCiliumIPv4(str)
	if err != nil {
		return fmt.Errorf("Invalid CiliumIPv4 '%s': %s", str, err)
	}

	*ip = c
	return nil
}

// Returns true if the IPv4 address is a valid IP for a container
// To be valid must obey to the following rules:
// - Node ID, bits from 0 to 16, must be different than 0
// - Endpoint ID, bits from 16 to 32, must be different than 0
func (ip CiliumIPv4) ValidContainerIP() bool {
	return ip.NodeID() != 0 && ip.EndpointID() != 0
}

// Returns true if the IPv4 address is a valid IP of a node
func (ip CiliumIPv4) ValidNodeIP() bool {
	// Unlike IPv6, a node address looks the same as a container address
	return ip.ValidContainerIP()
}

// NodeIP() return the node's IP based on an endpoint IP
// of the local node
func (ip CiliumIPv4) NodeIP() net.IP {
	nodeIP := make(net.IP, len(ip))
	copy(nodeIP, ip)
	nodeIP[3] = 1

	return nodeIP
}
