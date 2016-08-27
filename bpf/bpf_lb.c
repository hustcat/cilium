/*
 *  Copyright (C) 2016 Authors of Cilium
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <lb_config.h>
#include <netdev_config.h>

#include <bpf/api.h>

#include <stdint.h>
#include <stdio.h>

#include "lib/common.h"
#include "lib/maps.h"
#include "lib/ipv6.h"
#include "lib/icmp6.h"
#include "lib/l4.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/drop.h"
#include "lib/lb.h"

static inline int handle_ipv6(struct __sk_buff *skb)
{
	__u8 router_ip[] = ROUTER_IP;
	__u8 nexthdr;
	__u32 hash;
	__u16 slave;
	__be32 sum;
	int l4_off, csum_off = 0, ret, csum_flags = 0;
	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;
	union v6addr lb_ip;
	struct lb6_key key = {};
	struct lb6_service *svc;
	struct ipv6hdr *ip6 = data + ETH_HLEN;
	union v6addr *dst = (union v6addr *) &ip6->daddr;
	union macaddr lb_mac = NODE_MAC;

	ipv6_addr_copy(&lb_ip, (union v6addr *)router_ip);

	if (data + ETH_HLEN + sizeof(*ip6) > data_end)
		return DROP_INVALID;

	ipv6_addr_copy(&key.address, dst);

	if (ipv6_addrcmp(&key.address, &lb_ip))
		return TC_ACT_OK;

	cilium_trace_capture(skb, DBG_CAPTURE_FROM_LB, skb->ingress_ifindex);
	nexthdr = ip6->nexthdr;
	l4_off = ETH_HLEN + ipv6_hdrlen(skb, ETH_HLEN, &nexthdr);

#ifdef HANDLE_NS
	if (unlikely(nexthdr == IPPROTO_ICMPV6)) {
		ret = icmp6_handle(skb, ETH_HLEN, ip6);
		if (IS_ERR(ret))
			return ret;

	}
#endif

	ret = lb6_extract_key(skb, ip6, nexthdr, l4_off, &key, &csum_off, &csum_flags);
	if (IS_ERR(ret))
		return ret;

	svc = lb6_lookup_service(skb, &key);
	if (svc == NULL) {
		/* Pass packets to the stack which should not be loadbalanced */
		return TC_ACT_OK;
	}

	hash = get_hash_recalc(skb);
	slave = (hash % svc->count) + 1;
	cilium_trace(skb, DBG_PKT_HASH, hash, slave);

	if (!(svc = lb6_lookup_slave(skb, &key, slave)))
		return DROP_NO_SERVICE;

	if (csum_off && key.dport != svc->port) {
		/* FIXME: Store in network byte order */
		__u16 tmp = htons(svc->port);
		//cilium_trace(skb, DBG_GENERIC, svc->lxc[idx].port, 0);
		/* Port offsets for UDP and TCP are the same */
		ret = l4_modify_port(skb, l4_off + TCP_DPORT_OFF,
				     csum_off, tmp,
				     htons(key.dport));
		if (IS_ERR(ret))
			return ret;
	}

	ipv6_store_daddr(skb, svc->target.addr, ETH_HLEN);
	sum = csum_diff(key.address.addr, 16, svc->target.addr, 16, 0);
	if (csum_off && l4_csum_replace(skb, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	eth_store_saddr(skb, lb_mac.addr, 0);

	/* Send the packet to the stack */
	cilium_trace_capture(skb, DBG_CAPTURE_DELIVERY, 0);
	return TC_ACT_OK;
}

__section("from-netdev")
int from_netdev(struct __sk_buff *skb)
{
	int ret;

	switch (skb->protocol) {
	case __constant_htons(ETH_P_IPV6):
		/* This is considered the fast path, no tail call */
		ret = handle_ipv6(skb);
		break;

	default:
		/* Pass unknown traffic to the stack */
		ret = TC_ACT_OK;
	}

	if (IS_ERR(ret))
		return send_drop_notify_error(skb, ret, TC_ACT_SHOT);

	return ret;
}

BPF_LICENSE("GPL");
