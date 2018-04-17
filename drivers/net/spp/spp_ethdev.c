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

#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ethdev_pci.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_string_fns.h>
#include <rte_kvargs.h>
#include <rte_errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include "spp.h"


static const struct rte_pci_id pci_id_spp_map[] = {
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_AMAZON,
			 PCI_DEVICE_ID_SDE_LOOPBACK_CL) },
	{ .device_id = 0 },
};

struct eth_spp_xstats_name_off {
	char		name[RTE_ETH_XSTATS_NAME_SIZE];
	uint64_t	offset;
};

static const
struct eth_spp_xstats_name_off spp_rx_xstats_strings[] = {
	{ "rx_no_last_seg",
	  offsetof(struct spp_rx_stats, no_last_seg) },
	{ "rx_seg_packets",
	  offsetof(struct spp_rx_stats, seg_packets) },
	{ "rx_sde_errors",
	  offsetof(struct spp_rx_stats, sde_errors) },
};

static const
struct eth_spp_xstats_name_off spp_tx_xstats_strings[] = {
	{ "tx_none_avail",
	  offsetof(struct spp_tx_stats, no_tx_avail) },
	{ "tx_seg_packets",
	  offsetof(struct spp_tx_stats, seg_packets) },
	{ "tx_sde_errors",
	  offsetof(struct spp_tx_stats, sde_errors) },
};

static int
eth_spp_configure(__rte_unused struct rte_eth_dev *eth_dev)
{
	return 0;
}

static int
eth_spp_start(struct rte_eth_dev *eth_dev)
{
	eth_dev->data->dev_link.link_status = ETH_LINK_UP;
	return 0;
}

static void
eth_spp_stop(struct rte_eth_dev *eth_dev)
{
	eth_dev->data->dev_link.link_status = ETH_LINK_DOWN;
}

static int
eth_spp_set_link_down(struct rte_eth_dev *eth_dev)
{
	eth_dev->data->dev_link.link_status = ETH_LINK_DOWN;
	return 0;
}

static int
eth_spp_set_link_up(struct rte_eth_dev *eth_dev)
{
	eth_dev->data->dev_link.link_status = ETH_LINK_UP;
	return 0;
}

static void
eth_spp_info_get(struct rte_eth_dev		*eth_dev,
		 struct rte_eth_dev_info	*dev_info)
{
	struct spp_dev *spp_dev = eth_dev->data->dev_private;

	dev_info->max_mac_addrs = 1;
	dev_info->max_rx_pktlen = (uint32_t)-1;
	dev_info->max_rx_queues = spp_dev->dev_cap.num_rx_channels;
	dev_info->max_tx_queues = spp_dev->dev_cap.num_tx_channels;
	dev_info->min_rx_bufsize = 0;

	dev_info->rx_desc_lim.nb_max = SPP_RX_RING_DESC_MAX;
	dev_info->rx_desc_lim.nb_min = SPP_RX_RING_DESC_MIN;
	dev_info->rx_desc_lim.nb_align = SPP_RX_RING_DESC_ALIGN;

	dev_info->tx_desc_lim.nb_max = SPP_TX_RING_DESC_MAX;
	dev_info->tx_desc_lim.nb_min = SPP_TX_RING_DESC_MIN;
	dev_info->tx_desc_lim.nb_align = SPP_TX_RING_DESC_ALIGN;

	/* RX defaults: uses the RX channel 0 capabilities */
	dev_info->default_rxportconf.ring_size =
		spp_dev->dev_cap.rx_chan_cap[0].num_descs;

	/* TX defaults: uses the TX channel 0 capabilities */
	dev_info->default_txportconf.ring_size =
		spp_dev->dev_cap.tx_chan_cap[0].num_descs;
}

static int
eth_spp_stats_get(struct rte_eth_dev *eth_dev, struct rte_eth_stats *stats)
{
	struct spp_dev *spp_dev = eth_dev->data->dev_private;
	int i;

	for (i = 0; i < spp_dev->dev_cap.num_rx_channels; i++) {
		struct spp_rx_stats *rx_stats = &spp_dev->rx_channels[i].stats;

		/* Single channel stats */
		stats->q_ipackets[i] = rx_stats->packets;
		stats->q_ibytes[i] = rx_stats->bytes;

		/* Accumulate accross TX/RX channel */
		stats->q_errors[i] += rx_stats->errors;

		/* Accumulate accross RX channels */
		stats->ipackets += rx_stats->packets;
		stats->ibytes += rx_stats->bytes;
		stats->imissed += rx_stats->missed;
		stats->ierrors += rx_stats->errors;
		stats->rx_nombuf += rx_stats->no_mbuf;
	}

	for (i = 0; i < spp_dev->dev_cap.num_tx_channels; i++) {
		struct spp_tx_stats *tx_stats = &spp_dev->tx_channels[i].stats;

		/* Single channel stats */
		stats->q_opackets[i] = tx_stats->packets;
		stats->q_obytes[i] = tx_stats->bytes;

		/* Accumulate accross TX/RX channel */
		stats->q_errors[i] = tx_stats->errors;

		/* Accumulate accross TX channels */
		stats->opackets += tx_stats->packets;
		stats->obytes += tx_stats->bytes;
		stats->oerrors += tx_stats->errors;
	}

	return 0;
}

static void
eth_spp_stats_reset(__rte_unused struct rte_eth_dev *eth_dev)
{
	struct spp_dev *spp_dev = eth_dev->data->dev_private;
	int i;

	for (i = 0; i < spp_dev->dev_cap.num_rx_channels; i++) {
		struct spp_rx_stats *rx_stats = &spp_dev->rx_channels[i].stats;

		memset(rx_stats, 0, sizeof(*rx_stats));
	}

	for (i = 0; i < spp_dev->dev_cap.num_tx_channels; i++) {
		struct spp_tx_stats *tx_stats = &spp_dev->tx_channels[i].stats;

		memset(tx_stats, 0, sizeof(*tx_stats));
	}
}

static int
eth_spp_xstats_get_names(__rte_unused struct rte_eth_dev	*dev,
			 struct rte_eth_xstat_name		*xstats_names,
			 __rte_unused unsigned			limit)
{
	uint32_t stat_count = 0;
	uint32_t i;

	if (xstats_names == NULL)
		return SIZEOF_ARRAY(spp_rx_xstats_strings) +
		       SIZEOF_ARRAY(spp_tx_xstats_strings);

	for (i = 0; i < SIZEOF_ARRAY(spp_rx_xstats_strings); i++) {
		snprintf(xstats_names[stat_count].name,
			 sizeof(xstats_names[stat_count].name),
			 "%s",
			 spp_rx_xstats_strings[i].name);

		stat_count++;
	}

	for (i = 0; i < SIZEOF_ARRAY(spp_tx_xstats_strings); i++) {
		snprintf(xstats_names[stat_count].name,
			 sizeof(xstats_names[stat_count].name),
			 "%s",
			 spp_tx_xstats_strings[i].name);

		stat_count++;
	}

	return stat_count;
}

static uint64_t
spp_get_rx_xstat(struct spp_dev *spp_dev, uint64_t stat_offset)
{
	uint64_t value = 0;
	int i;

	for (i = 0; i < spp_dev->dev_cap.num_rx_channels; i++) {
		struct spp_rx_stats *rx_stats = &spp_dev->rx_channels[i].stats;

		value += *(uint64_t *)(((char *)rx_stats) + stat_offset);
	}

	return value;
}

static uint64_t
spp_get_tx_xstat(struct spp_dev *spp_dev, uint64_t stat_offset)
{
	uint64_t value = 0;
	int i;

	for (i = 0; i < spp_dev->dev_cap.num_tx_channels; i++) {
		struct spp_tx_stats *tx_stats = &spp_dev->tx_channels[i].stats;

		value += *(uint64_t *)(((char *)tx_stats) + stat_offset);
	}

	return value;
}

static int
eth_spp_xstats_get(struct rte_eth_dev *eth_dev, struct rte_eth_xstat *xstats,
		   unsigned int n)
{
	struct spp_dev *spp_dev = eth_dev->data->dev_private;
	uint32_t total_stat_count;
	uint32_t stat_count = 0;
	uint32_t i;

	total_stat_count = SIZEOF_ARRAY(spp_rx_xstats_strings) +
			   SIZEOF_ARRAY(spp_tx_xstats_strings);

	if (n < total_stat_count)
		return total_stat_count;

	for (i = 0; i < SIZEOF_ARRAY(spp_rx_xstats_strings); i++) {
		xstats[stat_count].value =
			spp_get_rx_xstat(spp_dev,
					 spp_rx_xstats_strings[i].offset);
		xstats[stat_count].id = stat_count;
		stat_count++;
	}

	for (i = 0; i < SIZEOF_ARRAY(spp_tx_xstats_strings); i++) {
		xstats[stat_count].value =
			spp_get_tx_xstat(spp_dev,
					 spp_tx_xstats_strings[i].offset);
		xstats[stat_count].id = stat_count;
		stat_count++;
	}

#if defined(SPP_DBG_XSTATS_DEV_DISPLAY)
	spp_dev_display(spp_dev);
#endif

	return stat_count;
}

static int
eth_spp_link_update(struct rte_eth_dev	*eth_dev,
		    __rte_unused int	wait_to_complete)
{
	struct rte_eth_link *link = &eth_dev->data->dev_link;

	link->link_speed = ETH_SPEED_NUM_10G;
	link->link_duplex = ETH_LINK_FULL_DUPLEX;
	link->link_autoneg = ETH_LINK_SPEED_AUTONEG;
	link->link_status = ETH_LINK_UP;

	return 0;
}

static int
eth_spp_queue_start_stop_noop(__rte_unused struct rte_eth_dev	*eth_dev,
			      __rte_unused uint16_t		queue_id)
{
	return 0;
}

static const struct eth_dev_ops eth_spp_ops = {
	.dev_start		= eth_spp_start,
	.dev_stop		= eth_spp_stop,
	.dev_set_link_up	= eth_spp_set_link_up,
	.dev_set_link_down	= eth_spp_set_link_down,
	.dev_configure		= eth_spp_configure,
	.dev_infos_get		= eth_spp_info_get,
	.rx_queue_setup		= spp_rx_queue_setup,
	.tx_queue_setup		= spp_tx_queue_setup,
	.rx_queue_release	= spp_rx_queue_release,
	.tx_queue_release	= spp_tx_queue_release,
	.rx_queue_start		= eth_spp_queue_start_stop_noop,
	.tx_queue_start		= eth_spp_queue_start_stop_noop,
	.rx_queue_stop		= eth_spp_queue_start_stop_noop,
	.tx_queue_stop		= eth_spp_queue_start_stop_noop,
	.link_update		= eth_spp_link_update,
	.stats_get		= eth_spp_stats_get,
	.stats_reset		= eth_spp_stats_reset,
	.xstats_get		= eth_spp_xstats_get,
	.xstats_get_names	= eth_spp_xstats_get_names,
	.xstats_reset		= eth_spp_stats_reset,
};

static int
eth_spp_init(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev;
	struct spp_dev *spp_dev = (struct spp_dev *)eth_dev->data->dev_private;
	int ret = 0;

	static int num_spp_devs;

	memset(spp_dev, 0, sizeof(struct spp_dev));

	eth_dev->dev_ops = &eth_spp_ops;
	eth_dev->rx_pkt_burst = &spp_rx_pkt_burst;
	eth_dev->tx_pkt_burst = &spp_tx_pkt_burst;
	spp_dev->rte_eth_dev_data = eth_dev->data;
	spp_dev->rte_eth_dev = eth_dev;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	spp_dev->pci_dev = pci_dev;

	SPP_INIT_LOG(DEBUG, "Initializing %x:%x:%x.%d",
		     pci_dev->addr.domain,
		     pci_dev->addr.bus,
		     pci_dev->addr.devid,
		     pci_dev->addr.function);

	SPP_INIT_LOG(DEBUG,
		     "reg_mem: virt=%p, phys=0x%" PRIx64 ", len=%" PRIu64,
		     pci_dev->mem_resource[SPP_SDE_REGS_BAR].addr,
		     pci_dev->mem_resource[SPP_SDE_REGS_BAR].phys_addr,
		     pci_dev->mem_resource[SPP_SDE_REGS_BAR].len);

	spp_dev->reg_mem = pci_dev->mem_resource[SPP_SDE_REGS_BAR].addr;
	spp_dev->wc_mem = pci_dev->mem_resource[SPP_SDE_REGS_BAR].addr;

	SPP_INIT_LOG(DEBUG, "wc_mem: virt=%p, len=%u",
		     spp_dev->wc_mem, SPP_SDE_WC_BAR_SIZE);

	spp_dev->dev_index = num_spp_devs;

	snprintf(spp_dev->name, sizeof(spp_dev->name), "spp_%d",
		 spp_dev->dev_index);

	/* Copy MAC address and point DPDK to it */
	eth_dev->data->mac_addrs = &spp_dev->ether_addr;

	ret = spp_dev_reset(spp_dev);
	if (ret != 0) {
		SPP_LOG(ERR, "spp_dev_reset failed, ret=%d", ret);
		goto out;
	}

	ret = spp_dev_cap_get(spp_dev, &spp_dev->dev_cap);
	if (ret != 0) {
		SPP_LOG(ERR, "spp_dev_cap_get failed, ret=%d", ret);
		goto out;
	}

	num_spp_devs++;
out:
	return ret;
}

static int
eth_spp_uninit(struct rte_eth_dev *eth_dev)
{
	(void)eth_dev;
	return 0;
}

static int
eth_spp_pci_probe(__rte_unused struct rte_pci_driver	*pci_drv,
		  struct rte_pci_device			*pci_dev)
{
	return rte_eth_dev_pci_generic_probe(pci_dev,
					     sizeof(struct spp_dev),
					     eth_spp_init);
}

static int
eth_spp_pci_remove(struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_remove(pci_dev, eth_spp_uninit);
}

static struct rte_pci_driver rte_spp_pmd = {
	.id_table	= pci_id_spp_map,
	.probe		= eth_spp_pci_probe,
	.drv_flags	= RTE_PCI_DRV_NEED_MAPPING,
	.remove		= eth_spp_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_spp, rte_spp_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_spp, pci_id_spp_map);
RTE_PMD_REGISTER_KMOD_DEP(net_spp, "* igb_uio | uio_pci_generic | vfio-pci");
