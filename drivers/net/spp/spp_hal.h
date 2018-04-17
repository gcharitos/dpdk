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

#ifndef _SPP_HAL_H_
#define _SPP_HAL_H_

#include "spp_hal_regs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SPP_RING_MASK(ring_size)        ((ring_size) - 1)
#define SPP_RING_IDX(idx, ring_size)    ((idx) & SPP_RING_MASK(ring_size))
#define SPP_RING_IDX_NEXT(idx, ring_size)       (((idx) + 1) & \
						 SPP_RING_MASK(ring_size))
#define SPP_CONF_SENTINAL                0x12349876

struct spp_rx_chan_cap {
	/* See SPP_REG_C2H_DESC_INFO */
	uint16_t	flags;
	uint16_t	num_descs;
};

struct spp_tx_chan_cap {
	/* See SPP_REG_H2C_DESC_INFO */
	uint16_t	flags;
	uint16_t	num_descs;
};

struct spp_dev_cap {
	/* See SPP_REG_SDE_INFO */
	uint32_t		flags;
	uint8_t			num_rx_channels;
	uint8_t			num_tx_channels;
	struct spp_rx_chan_cap	rx_chan_cap[SPP_RX_CHANNELS_MAX];
	struct spp_tx_chan_cap	tx_chan_cap[SPP_TX_CHANNELS_MAX];
};

struct spp_sw_desc {
	struct rte_mbuf *mbuf;
};

struct spp_sw_rx_info {
	struct spp_sw_desc	sw_ring[SPP_RX_RING_DESC_MAX];
	struct rte_mempool	*mb_pool;
};

struct spp_sw_tx_info {
	struct spp_sw_desc sw_ring[SPP_TX_RING_DESC_MAX];
};

struct spp_rx_info {
	/* See SPP_REG_C2H_DESC_INFO */
	uint32_t		flags;
	struct spp_rx_desc	*rx_desc;
	struct spp_wb_meta_desc *wb_meta_ring;
	struct spp_rx_status	*rx_status;
	rte_iova_t		wb_meta_ring_phys_addr;
	rte_iova_t		rx_desc_phys_addr;
	rte_iova_t		rx_status_phys_addr;
	const void		*mem_zone;
};

struct spp_tx_info {
	/* See SPP_REG_H2C_DESC_INFO */
	uint32_t		flags;
	struct spp_tx_desc	*tx_desc;
	struct spp_tx_status	*tx_status;
	rte_iova_t		tx_desc_phys_addr;
	rte_iova_t		tx_status_phys_addr;
	const void		*mem_zone;
};

struct spp_dev;

struct spp_tx_stats {
	uint64_t	packets;
	uint64_t	bytes;
	uint64_t	errors;
	uint64_t	no_tx_avail;
	uint64_t	seg_packets;
	uint64_t	sde_errors;
};

struct spp_tx_channel {
	uint32_t				configured;
	uint16_t				chan_index;

	uint16_t				write;
	uint16_t				next_to_clean;
	uint16_t				pad;
	uint32_t				ring_size;

	uint8_t __iomem				*reg_mem;
	uint8_t __iomem				*wc_mem;

#if defined(SPP_DBG_USE_DESC_SEQ_NUM)
	uint64_t				desc_seq_num;
#endif
#if defined(SPP_DBG_USE_MBUF_SEQ_NUM)
	uint64_t				mbuf_seq_num;
#endif

	struct spp_sw_tx_info sw_tx_info	__rte_cache_aligned;
	struct spp_tx_info tx_info		__rte_cache_aligned;
	struct spp_tx_stats stats		__rte_cache_aligned;

	struct spp_dev				*spp_dev;
};

struct spp_rx_stats {
	uint64_t	packets;
	uint64_t	bytes;
	uint64_t	missed;
	uint64_t	errors;
	uint64_t	no_mbuf;
	uint64_t	no_last_seg;
	uint64_t	seg_packets;
	uint64_t	sde_errors;
};

struct spp_rx_channel {
	uint32_t				configured;
	uint16_t				chan_index;

	uint16_t				next_to_fill;
	uint16_t				read;
	uint16_t				pad;
	uint32_t				ring_size;

	uint8_t __iomem				*reg_mem;
	uint8_t __iomem				*wc_mem;

#if defined(SPP_DBG_USE_DESC_SEQ_NUM)
	uint64_t				desc_seq_num;
#endif
#if defined(SPP_DBG_USE_MBUF_SEQ_NUM)
	uint64_t				mbuf_seq_num;
#endif

	struct spp_sw_rx_info sw_rx_info	__rte_cache_aligned;
	struct spp_rx_info rx_info		__rte_cache_aligned;
	struct spp_rx_stats stats		__rte_cache_aligned;

	struct spp_dev				*spp_dev;
};

int spp_rx_queue_setup(struct rte_eth_dev *dev, uint16_t rx_queue_id,
		       uint16_t nb_rx_desc, unsigned int socket_id,
		       const struct rte_eth_rxconf *rx_conf,
		       struct rte_mempool *mb_pool);
void spp_rx_queue_release(void *q);

int spp_tx_queue_setup(struct rte_eth_dev *dev, uint16_t tx_queue_id,
		       uint16_t nb_tx_desc, unsigned int socket_id,
		       const struct rte_eth_txconf *tx_conf);
void spp_tx_queue_release(void *q);

uint16_t spp_rx_pkt_burst(void *q, struct rte_mbuf **bufs, uint16_t nb_bufs);
uint16_t spp_tx_pkt_burst(void *q, struct rte_mbuf **bufs, uint16_t nb_bufs);

int spp_dev_reset(struct spp_dev *spp_dev);
int spp_dev_cap_get(struct spp_dev *spp_dev, struct spp_dev_cap *dev_cap);
void spp_dev_display(struct spp_dev *spp_dev);

#ifdef __cplusplus
}
#endif

#endif
