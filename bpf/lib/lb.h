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
#ifndef __LB_H_
#define __LB_H_

/* FIXME: Make configurable */
#define CILIUM_LB_MAP_SIZE	1024

__BPF_MAP(cilium_lb6_state, BPF_MAP_TYPE_HASH, 0,
	  sizeof(__u16), sizeof(struct lb6_state),
	  PIN_GLOBAL_NS, CILIUM_LB_MAP_SIZE);

__BPF_MAP(cilium_lb6_services, BPF_MAP_TYPE_HASH, 0,
	  sizeof(struct lb6_key), sizeof(struct lb6_service),
	  PIN_GLOBAL_NS, CILIUM_LB_MAP_SIZE);

/** Perform DSR SNAT based on state
 * @arg skb		packet
 * @arg l4_off		offset to L4
 * @arg csum_off	offset to L4 checksum field
 * @arg csum_flags	checksum flags
 * @arg state		state
 * @arg tuple		tuple
 */
static inline int lb_dsr_snat(struct __sk_buff *skb, int l4_off, int csum_off,
			      int csum_flags, __u16 state, struct ipv6_ct_tuple *tuple)
{
	union v6addr tmp, sip;
	struct lb6_state *st;
	__u16 sport;
	__be32 sum;
	int ret;

	st = map_lookup_elem(&cilium_lb6_state, &state);
	if (st == NULL) {
		cilium_trace(skb, DBG_LB_STATE_LOOKUP_FAIL, state, 0);
		return 0;
	}

	switch (tuple->nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		if (st->port) {
			/* Port offsets for UDP and TCP are the same */
			ret = l4_load_port(skb, l4_off + TCP_SPORT_OFF, &sport);
			if (IS_ERR(ret))
				return ret;

			if (st->port != sport) {
				ret = l4_modify_port(skb, l4_off + TCP_SPORT_OFF,
						     l4_off + csum_off, st->port, sport);
				if (IS_ERR(ret))
					return ret;
			}
		}
		break;

	case IPPROTO_ICMPV6:
		break;

	default:
		return DROP_UNKNOWN_L4;
	}

	if (ipv6_load_saddr(skb, ETH_HLEN, &sip) < 0)
		return DROP_INVALID;

	ipv6_addr_copy(&tmp, &st->address);
	ret = ipv6_store_saddr(skb, tmp.addr, ETH_HLEN);
	if (IS_ERR(ret))
		return DROP_WRITE_ERROR;

	sum = csum_diff(sip.addr, 16, tmp.addr, 16, 0);
	if (l4_csum_replace(skb, l4_off + csum_off, 0, sum, csum_flags | BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	return 0;
}

/** Extract LB key from packet
 * @arg skb		packet
 * @arg ip6		Pointer to ipv6 header
 * @arg nexthdr		L4 nexthdr
 * @arg l4_off		Offset to L4 header
 * @arg key		Pointer to store LB key in
 * @arg csum_off	Pointer to store L4 checksum field offset  in
 * @arg csum_flags	Pointer to store L4 checksum flags
 *
 * Expects the skb to be validated for direct packet access up to L4. Fills
 * lb6_key based on L4 nexthdr.
 *
 * Returns:
 *   - TC_ACT_OK on successful extraction
 *   - DROP_UNKNOWN_L4 if packet should be ignore (sent to stack)
 *   - Negative error code
 */
static inline int __inline__ lb6_extract_key(struct __sk_buff *skb, struct ipv6hdr *ip6,
					     __u8 nexthdr, int l4_off, struct lb6_key *key,
					     int *csum_off, int *csum_flags)
{
	union v6addr *dst = (union v6addr *) &ip6->daddr;
	int ret;

	ipv6_addr_copy(&key->address, dst);

	switch (nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		/* Port offsets for UDP and TCP are the same */
		ret = l4_load_port(skb, l4_off + TCP_DPORT_OFF, &key->dport);
		if (IS_ERR(ret))
			return ret;
		break;

	case IPPROTO_ICMPV6:
		break;

	default:
		/* Pass unknown L4 to stack */
		return DROP_UNKNOWN_L4;
	}

	*csum_off = l4_csum_offset_and_flags(nexthdr, csum_flags);

	return TC_ACT_OK;
}

static inline struct lb6_service *lb6_lookup_service(struct __sk_buff *skb,
						    struct lb6_key *key)
{
	struct lb6_service *svc;

	svc = map_lookup_elem(&cilium_lb6_services, key);
	if (svc && svc->count != 0)
		return svc;

	if (key->dport != 0) {
		key->dport = 0;
		svc = map_lookup_elem(&cilium_lb6_services, key);
		if (svc && svc->count != 0)
			return svc;
	}

	cilium_trace(skb, DBG_LB_LOOKUP_FAIL_MASTER, key->address.p4, ntohs(key->dport));
	return NULL;
}

static inline struct lb6_service *lb6_lookup_slave(struct __sk_buff *skb,
						   struct lb6_key *key, __u16 slave)
{
	struct lb6_service *svc;

	key->slave = slave;
	svc = map_lookup_elem(&cilium_lb6_services, key);
	if (svc != NULL)
		return svc;

	cilium_trace(skb, DBG_LB_LOOKUP_FAIL_SLAVE, key->slave, ntohs(key->dport));
	return NULL;
}

static inline int __inline__ lb6_local(struct __sk_buff *skb, __u8 nexthdr, int l3_off, int l4_off,
				       int csum_off, int csum_flags, struct lb6_key *key,
				       struct ipv6_ct_tuple *tuple, struct lb6_service *svc)
{
	__u16 slave;
	__u32 hash;
	int ret;

	hash = get_hash_recalc(skb);
	/* Slave 0 is reserved for the master slot */
	slave = (hash % svc->count) + 1;
	cilium_trace(skb, DBG_PKT_HASH, hash, slave);

	if (!(svc = lb6_lookup_slave(skb, key, slave)))
		return DROP_NO_SERVICE;

	ipv6_addr_copy(&tuple->addr, &svc->target);
	ipv6_store_daddr(skb, tuple->addr.addr, l3_off);

	if (csum_off) {
		__be32 sum = csum_diff(key->address.addr, 16, tuple->addr.addr, 16, 0);
		if (l4_csum_replace(skb, l4_off + csum_off, 0, sum, BPF_F_PSEUDO_HDR | csum_flags) < 0)
			return DROP_CSUM_L4;
	}

	if (svc->port && key->dport != svc->port &&
	    (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP)) {
		__u16 tmp = svc->port;
		/* Port offsets for UDP and TCP are the same */
		ret = l4_modify_port(skb, l4_off + TCP_DPORT_OFF,
				     l4_off + csum_off, tmp,
				     key->dport);
		if (IS_ERR(ret))
			return ret;
	}

	return TC_ACT_OK;
}

#endif /* __LB_H_ */
