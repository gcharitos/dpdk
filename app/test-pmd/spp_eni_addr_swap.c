/*
 * Copyright 2015-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may
 * not use this file except in compliance with the License. A copy of the
 * License is located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>

#include <sys/queue.h>
#include <sys/stat.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_string_fns.h>
#include <rte_flow.h>

#include "testpmd.h"

#define IPV6_ADDR_SIZE 16

/*
 * SPP-ENI chaining address swap forwarding mode: Swap the source and the
 * destination Ethernet addresses and source and destination IP addresses
 * of packets before forwarding them.
 *
 * NOTE:
 * The SPP Virtual Ethernet device defaults to a zero mac address.
 * We use this fact to know when to swap addresses for ENI (e.g. when
 * macaddr[0] != 0, swap addresses).
 */
static inline void
ipv4_addr_swap(struct ipv4_hdr *ipv4_hdr)
{
	uint32_t ipv4_addr_tmp;

	ipv4_addr_tmp = ipv4_hdr->src_addr;
	ipv4_hdr->src_addr = ipv4_hdr->dst_addr;
	ipv4_hdr->dst_addr = ipv4_addr_tmp;
}

static inline void
ipv6_addr_swap(struct ipv6_hdr *ipv6_hdr)
{
	uint8_t ipv6_addr_tmp[IPV6_ADDR_SIZE];

	memcpy(ipv6_addr_tmp, ipv6_hdr->src_addr, IPV6_ADDR_SIZE);
	memcpy(ipv6_hdr->src_addr, ipv6_hdr->dst_addr, IPV6_ADDR_SIZE);
	memcpy(ipv6_hdr->dst_addr, ipv6_addr_tmp, IPV6_ADDR_SIZE);
}

static void
pkt_burst_spp_eni_addr_swap(struct fwd_stream *fs)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_port *txp;
	struct rte_mbuf *mb;
	struct ether_hdr *eth_hdr;
	struct ether_addr addr;
	uint16_t nb_rx;
	uint16_t nb_tx;
	uint16_t i;
	uint32_t retry;
	uint64_t ol_flags = 0;
	uint64_t tx_offloads;

#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
	uint64_t start_tsc;
	uint64_t end_tsc;
	uint64_t core_cycles;
#endif
	struct ipv4_hdr *ipv4_hdr;
	struct ipv6_hdr *ipv6_hdr;

#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
	start_tsc = rte_rdtsc();
#endif

	/*
	 * Receive a burst of packets and forward them.
	 */
	nb_rx = rte_eth_rx_burst(fs->rx_port, fs->rx_queue, pkts_burst,
				 nb_pkt_per_burst);
	if (unlikely(nb_rx == 0))
		return;

#ifdef RTE_TEST_PMD_RECORD_BURST_STATS
	fs->rx_burst_stats.pkt_burst_spread[nb_rx]++;
#endif
	fs->rx_packets += nb_rx;
	txp = &ports[fs->tx_port];
	tx_offloads = txp->dev_conf.txmode.offloads;
	if (tx_offloads & DEV_TX_OFFLOAD_VLAN_INSERT)
		ol_flags = PKT_TX_VLAN_PKT;
	if (tx_offloads & DEV_TX_OFFLOAD_QINQ_INSERT)
		ol_flags |= PKT_TX_QINQ_PKT;
	if (tx_offloads & DEV_TX_OFFLOAD_MACSEC_INSERT)
		ol_flags |= PKT_TX_MACSEC;
	for (i = 0; i < nb_rx; i++) {
		if (likely(i < nb_rx - 1))
			rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[i + 1],
						       void *));
		mb = pkts_burst[i];
		eth_hdr = rte_pktmbuf_mtod(mb, struct ether_hdr *);

		/* Do not swap for SPP PMD (default MAC addr==0) */
		if (txp->eth_addr.addr_bytes[0] != 0) {
			/* Swap dest and src mac addresses. */
			ether_addr_copy(&eth_hdr->d_addr, &addr);
			ether_addr_copy(&eth_hdr->s_addr, &eth_hdr->d_addr);
			ether_addr_copy(&addr, &eth_hdr->s_addr);

			if (likely(eth_hdr->ether_type ==
				   htons(ETHER_TYPE_IPv4))) {
				/* Swap dest and src IPv4 addresses */
				ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
				ipv4_addr_swap(ipv4_hdr);
			} else if (eth_hdr->ether_type ==
				   htons(ETHER_TYPE_IPv6)) {
				/* Swap dest and src IPv6 addresses */
				ipv6_hdr = (struct ipv6_hdr *)(eth_hdr + 1);
				ipv6_addr_swap(ipv6_hdr);
			}
		}

		mb->ol_flags &= IND_ATTACHED_MBUF | EXT_ATTACHED_MBUF;
		mb->ol_flags |= ol_flags;
		mb->l2_len = sizeof(struct ether_hdr);
		mb->l3_len = sizeof(struct ipv4_hdr);
		mb->vlan_tci = txp->tx_vlan_id;
		mb->vlan_tci_outer = txp->tx_vlan_id_outer;
	}
	nb_tx = rte_eth_tx_burst(fs->tx_port, fs->tx_queue, pkts_burst, nb_rx);
	/*
	 * Retry if necessary
	 */
	if (unlikely(nb_tx < nb_rx) && fs->retry_enabled) {
		retry = 0;
		while (nb_tx < nb_rx && retry++ < burst_tx_retry_num) {
			rte_delay_us(burst_tx_delay_time);
			nb_tx += rte_eth_tx_burst(fs->tx_port, fs->tx_queue,
						  &pkts_burst[nb_tx],
						  nb_rx - nb_tx);
		}
	}
	fs->tx_packets += nb_tx;
#ifdef RTE_TEST_PMD_RECORD_BURST_STATS
	fs->tx_burst_stats.pkt_burst_spread[nb_tx]++;
#endif
	if (unlikely(nb_tx < nb_rx)) {
		fs->fwd_dropped += (nb_rx - nb_tx);
		do
			rte_pktmbuf_free(pkts_burst[nb_tx]);
		while (++nb_tx < nb_rx);
	}
#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
	end_tsc = rte_rdtsc();
	core_cycles = (end_tsc - start_tsc);
	fs->core_cycles = (uint64_t)(fs->core_cycles + core_cycles);
#endif
}

struct fwd_engine spp_eni_addr_swap_engine = {
	.fwd_mode_name	= "spp-eni-addr-swap",
	.port_fwd_begin = NULL,
	.port_fwd_end	= NULL,
	.packet_fwd	= pkt_burst_spp_eni_addr_swap,
};
