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
#include <rte_io.h>
#include <rte_string_fns.h>
#include <rte_kvargs.h>
#include <rte_errno.h>
#include <unistd.h>
#include "spp.h"
#include "spp_hal_private.h"

static inline uint16_t
spp_tx_descs_to_clean(struct spp_tx_channel *tx_chan)
{
	return (spp_tx_channel_get_read_desc_completed(tx_chan) -
		tx_chan->next_to_clean) &
	       SPP_RING_MASK(tx_chan->ring_size);
}

static inline uint16_t
spp_tx_avail(struct spp_tx_channel *tx_chan)
{
	return (tx_chan->ring_size -
		((tx_chan->write -
		  tx_chan->next_to_clean) &
		 SPP_RING_MASK(tx_chan->ring_size))) - 1;
}

static inline uint16_t
spp_rx_descs_to_fill(struct spp_rx_channel *rx_chan)
{
	return (rx_chan->read - rx_chan->next_to_fill) &
	       SPP_RING_MASK(rx_chan->ring_size);
}

static inline int
spp_tx_process_status(struct spp_tx_channel *tx_chan)
{
	uint32_t status = tx_chan->tx_info.tx_status->status;

	if (unlikely(status)) {
		static uint32_t prev_status;

		if (status != prev_status) {
			tx_chan->stats.sde_errors++;
			SPP_LOG(ERR, "TX status error");
			spp_dbg_dump_tx_chan(tx_chan);
			prev_status = status;
		}
		return -EIO;
	}

	return 0;
}

static inline int
spp_rx_process_status(struct spp_rx_channel *rx_chan)
{
	uint32_t status = rx_chan->rx_info.rx_status->status;

	if (unlikely(status)) {
		static uint32_t prev_status;

		if (status != prev_status) {
			rx_chan->stats.sde_errors++;
			SPP_LOG(ERR, "RX status error");
			spp_dbg_dump_rx_chan(rx_chan);
			prev_status = status;
		}
		return -EIO;
	}

	return 0;
}

static inline struct rte_mbuf *
spp_consume_sw_desc(struct spp_sw_desc *sw_desc)
{
	struct rte_mbuf *mbuf;

	mbuf = sw_desc->mbuf;
	sw_desc->mbuf = NULL;

	return mbuf;
}

static int
spp_alloc_rx_channel_info(struct spp_rx_info *rx_info, int dev_index,
			  int chan_index, uint16_t num_descs,
			  unsigned int socket_id)
{
	const struct rte_memzone *mz;
	char z_name[RTE_MEMZONE_NAMESIZE];
	size_t wb_meta_desc_size;
	size_t wb_meta_ring_size;
	size_t rx_desc_size;
	size_t rx_status_size;
	size_t size = 0;
	rte_iova_t iova;        /* IO address */
	char *addr;             /* virtual address */
	int ret = 0;

#if defined(SPP_USE_AVX2)
#if defined(SPP_USE_COMPACT_DESCS)
	if (sizeof(struct spp_wb_meta_desc) != 8) {
		SPP_LOG(ERR,
			"spp_wb_meta_desc is not 8B, cannot use AVX2 spp_meta_desc_memset");
		ret = -EINVAL;
		goto out;
	}
	if (sizeof(struct spp_rx_desc) != 16) {
		SPP_LOG(ERR,
			"spp_rx_desc is not 16B, cannot use AVX2 spp_rx_desc_memcpy");
		ret = -EINVAL;
		goto out;
	}
#else
	if (sizeof(struct spp_wb_meta_desc) != 16) {
		SPP_LOG(ERR,
			"spp_wb_meta_desc is not 16B, cannot use AVX2 spp_meta_desc_memset");
		ret = -EINVAL;
		goto out;
	}
	if (sizeof(struct spp_rx_desc) != 16) {
		SPP_LOG(ERR,
			"spp_rx_desc is not 16B, cannot use AVX2 spp_rx_desc_memcpy");
		ret = -EINVAL;
		goto out;
	}
#endif
#endif

	wb_meta_desc_size = sizeof(struct spp_wb_meta_desc);
	wb_meta_ring_size = RTE_ALIGN(
		num_descs * wb_meta_desc_size,
		RTE_CACHE_LINE_SIZE);

	rx_status_size = RTE_ALIGN(sizeof(struct spp_rx_status),
				   RTE_CACHE_LINE_SIZE);

	rx_desc_size = RTE_ALIGN(sizeof(struct spp_rx_desc),
				 RTE_CACHE_LINE_SIZE);

	size = wb_meta_ring_size + rx_status_size + rx_desc_size;

	snprintf(z_name, sizeof(z_name),
		 "net_spp_rx_ring_%d_%d", dev_index, chan_index);
	mz = rte_memzone_reserve_aligned(
		z_name, size,
		socket_id,
		RTE_MEMZONE_2MB |
		RTE_MEMZONE_SIZE_HINT_ONLY |
		RTE_MEMZONE_IOVA_CONTIG,
		getpagesize());
	if (mz == NULL) {
		SPP_LOG(CRIT, "rte_memzone_reserve_aligned failed");
		ret = -ENOMEM;
		goto out;
	}
	if (mz->iova & 0x3) {
		SPP_LOG(CRIT, "rte_memzone_reserve_aligned iova is unaligned");
		ret = -ENOMEM;
		goto out;
	}

	iova = mz->iova;

	if ((unsigned long)mz->addr == iova) {
		size_t tmp_size;

		SPP_LOG(WARNING, "Memzone physical address same as virtual.");
		SPP_LOG(WARNING, "Using rte_mem_virt2iova()");
		for (tmp_size = 0; tmp_size < size; tmp_size += getpagesize())
			rte_mem_lock_page(((char *)mz->addr) + tmp_size);
		iova = rte_mem_virt2iova(mz->addr);
		if (iova == 0) {
			SPP_LOG(ERR,
				"could not map virtual address to physical memory");
			ret = -ENOMEM;
			goto out;
		}
	}

	addr = mz->addr;
	memset(addr, 0, size);

	rx_info->wb_meta_ring = (void *)addr;
	rx_info->wb_meta_ring_phys_addr = iova;
	addr += wb_meta_ring_size;
	iova += wb_meta_ring_size;

	rx_info->rx_status = (void *)addr;
	rx_info->rx_status_phys_addr = iova;
	addr += rx_status_size;
	iova += rx_status_size;

	rx_info->rx_desc = (void *)addr;
	rx_info->rx_desc_phys_addr = iova;
	addr += rx_desc_size;
	iova += rx_desc_size;

	rx_info->mem_zone = mz;

	SPP_LOG(DEBUG, "z_name=%s, wb_meta_ring virt=%p, phys=%p, size=%zu",
		z_name, rx_info->wb_meta_ring,
		(void *)rx_info->wb_meta_ring_phys_addr,
		wb_meta_ring_size);
	SPP_LOG(DEBUG, "z_name=%s, rx_status virt=%p, phys=%p, size=%zu",
		z_name, rx_info->rx_status,
		(void *)rx_info->rx_status_phys_addr,
		rx_status_size);
	SPP_LOG(DEBUG, "z_name=%s, rx_desc virt=%p, phys=%p, size=%zu",
		z_name, rx_info->rx_desc,
		(void *)rx_info->rx_desc_phys_addr,
		rx_desc_size);
out:
	return ret;
}

static int
spp_alloc_tx_channel_info(struct spp_tx_info *tx_info, int dev_index,
			  int chan_index, unsigned int socket_id)
{
	const struct rte_memzone *mz;
	char z_name[RTE_MEMZONE_NAMESIZE];
	size_t tx_desc_size;
	size_t tx_status_size;
	size_t size;
	rte_iova_t iova;        /* IO address. */
	char *addr;             /* virtual address. */
	int ret = 0;

#if defined(SPP_USE_AVX2)
#if defined(SPP_USE_COMPACT_DESCS)
	if (sizeof(struct spp_tx_desc) != 16) {
		SPP_LOG(ERR,
			"spp_tx_desc is not 16B, cannot use AVX2 spp_tx_desc_memcpy");
		ret = -EINVAL;
		goto out;
	}
#else
	if (sizeof(struct spp_tx_desc) != 32) {
		SPP_LOG(ERR,
			"spp_tx_desc is not 32B, cannot use AVX2 spp_tx_desc_memcpy");
		ret = -EINVAL;
		goto out;
	}
#endif
#endif

	tx_status_size = RTE_ALIGN(sizeof(struct spp_tx_status),
				   RTE_CACHE_LINE_SIZE);

	tx_desc_size = RTE_ALIGN(sizeof(struct spp_tx_desc),
				 RTE_CACHE_LINE_SIZE);

	size = tx_status_size + tx_desc_size;

	snprintf(z_name, sizeof(z_name),
		 "net_spp_tx_ring_%d_%d", dev_index, chan_index);
	mz = rte_memzone_reserve_aligned(
		z_name, size,
		socket_id,
		RTE_MEMZONE_2MB |
		RTE_MEMZONE_SIZE_HINT_ONLY |
		RTE_MEMZONE_IOVA_CONTIG,
		getpagesize());
	if (mz == NULL) {
		SPP_LOG(CRIT, "rte_memzone_reserve_aligned failed");
		ret = -ENOMEM;
		goto out;
	}
	if (mz->iova & 0x3) {
		SPP_LOG(CRIT, "rte_memzone_reserve_aligned iova is unaligned");
		ret = -ENOMEM;
		goto out;
	}

	iova = mz->iova;

	if ((unsigned long)mz->addr == iova) {
		size_t tmp_size;

		SPP_LOG(WARNING, "Memzone physical address same as virtual.");
		SPP_LOG(WARNING, "Using rte_mem_virt2iova()");
		for (tmp_size = 0; tmp_size < size; tmp_size += getpagesize())
			rte_mem_lock_page(((char *)mz->addr) + tmp_size);
		iova = rte_mem_virt2iova(mz->addr);
		if (iova == 0) {
			SPP_LOG(ERR,
				"could not map virtual address to physical memory");
			ret = -ENOMEM;
			goto out;
		}
	}

	addr = mz->addr;
	memset(addr, 0, size);

	tx_info->tx_status = (void *)addr;
	tx_info->tx_status_phys_addr = iova;
	addr += tx_status_size;
	iova += tx_status_size;

	tx_info->tx_desc = (void *)addr;
	tx_info->tx_desc_phys_addr = iova;
	addr += tx_desc_size;
	iova += tx_desc_size;

	tx_info->mem_zone = mz;

	SPP_LOG(DEBUG, "z_name=%s, tx_status virt=%p, phys=%p, size=%zu",
		z_name, tx_info->tx_status,
		(void *)tx_info->tx_status_phys_addr,
		tx_status_size);
	SPP_LOG(DEBUG, "z_name=%s, tx_desc virt=%p, phys=%p, size=%zu",
		z_name, tx_info->tx_desc,
		(void *)tx_info->tx_desc_phys_addr,
		tx_desc_size);
out:
	return ret;
}

static inline void
spp_rx_write_desc(struct spp_rx_channel *rx_chan, struct rte_mbuf *mbuf)
{
	struct spp_rx_info *rx_info = &rx_chan->rx_info;
	struct spp_rx_desc *rx_desc = rx_info->rx_desc;

	rx_desc->length = mbuf->buf_len - RTE_PKTMBUF_HEADROOM;
	rx_desc->phys_addr = mbuf->buf_iova + RTE_PKTMBUF_HEADROOM;

	spp_rx_desc_memcpy(rx_chan->wc_mem + SPP_C2H_DESC_RAM_BASE,
			   (uint8_t *)rx_desc);

#if defined(SPP_DBG_DUMP_DESCS)
	spp_dbg_dump_rx_desc(rx_chan, rx_desc);
#endif
}

static int
spp_fill_rx_channel(struct spp_rx_channel *rx_chan, uint16_t num_descs)
{
	int ret = 0;
	uint16_t next_to_fill = rx_chan->next_to_fill;
	struct spp_sw_desc *sw_ring = rx_chan->sw_rx_info.sw_ring;
	struct rte_mempool *mb_pool = rx_chan->sw_rx_info.mb_pool;
	struct rte_mbuf *mbuf;
	int i;

	for (i = 0; i < num_descs; i++) {
		struct spp_sw_desc *sw_desc = &sw_ring[next_to_fill];
		if (unlikely(sw_desc->mbuf != NULL)) {
			SPP_LOG(ERR, "next_to_fill mbuf != NULL");
			ret = -EINVAL;
			goto out;
		}

		mbuf = rte_pktmbuf_alloc(mb_pool);
		if (unlikely(mbuf == NULL)) {
			rx_chan->stats.no_mbuf++;
			SPP_LOG(DEBUG, "rte_pktmbuf_alloc failed");
			ret = -ENOMEM;
			goto out;
		}
		sw_desc->mbuf = mbuf;

		spp_rx_write_desc(rx_chan, mbuf);

		next_to_fill = SPP_RING_IDX_NEXT(next_to_fill,
						 rx_chan->ring_size);
	}

	rx_chan->next_to_fill = next_to_fill;
out:
	return ret;
}

static int
spp_init_rx_channel(struct spp_rx_channel *rx_chan, unsigned int socket_id)
{
	int ret = 0;

#if !defined(SPP_DBG_SW_LOOPBACK)
	uint32_t value;

	/* Perform a sanity check on the ring_size before the alloc */
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_CDT_LIMIT, 0);
	value = spp_rx_chan_reg_read(rx_chan, SPP_REG_C2H_CDT_LIMIT);
	if (value != rx_chan->ring_size) {
		SPP_LOG(ERR, "Unsupported ring_size=%u != %u",
			rx_chan->ring_size, value);
		ret = -EINVAL;
		goto out;
	}
#endif

	ret = spp_alloc_rx_channel_info(&rx_chan->rx_info,
					rx_chan->spp_dev->dev_index,
					rx_chan->chan_index,
					rx_chan->ring_size,
					socket_id);
	if (ret) {
		SPP_LOG(ERR, "spp_alloc_rx_channel_info failed, ret=%d", ret);
		goto out;
	}

	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_CDT_CONSUMED, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_CDT_LIMIT, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_COMP_CNT, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_DESC_FIFO, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_DESC_RAM_STATUS, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_DM_CFG, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_DM_STATUS, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_WB_CFG,
			      SPP_C2H_WB_CFG_ALL_EN);

	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_STATUS_WB_ADDR_LO,
			      rx_chan->rx_info.rx_status_phys_addr &
			      SPP_C2H_STATUS_WB_ADDR_LO_MASK);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_STATUS_WB_ADDR_HI,
			      rx_chan->rx_info.rx_status_phys_addr >>
			      SPP_C2H_STATUS_WB_ADDR_HI_SHIFT);

	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_WC_TO_CNT,
			      SPP_C2H_WC_TO_CNT_ALL);

	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_WB_META_RING_ADDR_LO,
			      rx_chan->rx_info.wb_meta_ring_phys_addr &
			      SPP_C2H_WB_META_RING_ADDR_LO_MASK);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_WB_META_RING_ADDR_HI,
			      rx_chan->rx_info.wb_meta_ring_phys_addr >>
			      SPP_C2H_WB_META_RING_ADDR_HI_SHIFT);

	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_WB_META_RING_SIZE,
			      rx_chan->ring_size *
			      sizeof(struct spp_wb_meta_desc));

	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_WB_META_RING_READ, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_WB_META_RING_WRITE, 0);

	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_WB_STATUS_ERR, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_WB_STATUS, 0);

	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_BUF_CFG, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_BUF_STATUS, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_BUF_IN_PKT_CNT, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_BUF_OUT_PKT_CNT, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_BUF_PTR, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_AUX_RAM_PTR, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_BUF_NUM_BYTES, 0);

	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_AXIS_PKT_CNT, 0);

	/* spp_alloc_rx_channel_info has already cleared the rx_info
	 * write-back memzone */
	rx_chan->rx_info.rx_status->desc_limit = rx_chan->ring_size;

	ret = spp_fill_rx_channel(rx_chan, rx_chan->ring_size);
	if (ret) {
		SPP_LOG(ERR, "spp_fill_rx_channel failed, ret=%d", ret);
		goto out;
	}

	rx_chan->next_to_fill = 0;
out:
	return ret;
}

static void
spp_free_rx_channel_sw_descs(struct spp_rx_channel *rx_chan)
{
	struct spp_sw_desc *sw_ring = rx_chan->sw_rx_info.sw_ring;
	struct rte_mbuf *mbuf;
	uint32_t i;

	for (i = 0; i < rx_chan->ring_size; i++) {
		struct spp_sw_desc *sw_desc = &sw_ring[i];

		mbuf = spp_consume_sw_desc(sw_desc);
		if (mbuf)
			/*
			 * rte_pktmbuf_free_seg handles the mbuf->next=NULL,
			 * and nb_segs=1
			 */
			rte_pktmbuf_free_seg(mbuf);
	}
}

static int
spp_destroy_rx_channel(struct spp_rx_channel *rx_chan)
{
	int ret = 0;

	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_CDT_CONSUMED, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_CDT_LIMIT, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_COMP_CNT, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_DESC_FIFO, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_DESC_RAM_STATUS, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_DM_CFG, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_DM_STATUS, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_WB_CFG, 0);

	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_STATUS_WB_ADDR_LO, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_STATUS_WB_ADDR_HI, 0);

	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_WC_TO_CNT, 0);

	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_WB_META_RING_ADDR_LO, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_WB_META_RING_ADDR_HI, 0);

	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_WB_META_RING_SIZE, 0);

	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_WB_META_RING_READ, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_WB_META_RING_WRITE, 0);

	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_WB_STATUS_ERR, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_WB_STATUS, 0);

	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_BUF_CFG, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_BUF_STATUS, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_BUF_IN_PKT_CNT, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_BUF_OUT_PKT_CNT, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_BUF_PTR, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_AUX_RAM_PTR, 0);
	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_BUF_NUM_BYTES, 0);

	spp_rx_chan_reg_write(rx_chan, SPP_REG_C2H_AXIS_PKT_CNT, 0);

	spp_free_rx_channel_sw_descs(rx_chan);

	if (rx_chan->rx_info.mem_zone) {
		ret = rte_memzone_free(rx_chan->rx_info.mem_zone);
		if (ret) {
			SPP_LOG(CRIT, "rte_memzone_free failed, ret=%d", ret);
			goto out;
		}
	}
out:
	return ret;
}

static int
spp_init_tx_channel(struct spp_tx_channel *tx_chan, unsigned int socket_id)
{
	int ret = 0;

#if !defined(SPP_DBG_SW_LOOPBACK)
	uint32_t value;

	/* Perform a sanity check on the ring_size before the alloc */
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_CDT_LIMIT, 0);
	value = spp_tx_chan_reg_read(tx_chan, SPP_REG_H2C_CDT_LIMIT);
	if (value != tx_chan->ring_size) {
		SPP_LOG(ERR, "Unsupported ring_size=%u != %u",
			tx_chan->ring_size, value);
		ret = -EINVAL;
		goto out;
	}
#endif

	ret = spp_alloc_tx_channel_info(&tx_chan->tx_info,
					tx_chan->spp_dev->dev_index,
					tx_chan->chan_index,
					socket_id);
	if (ret) {
		SPP_LOG(ERR, "spp_alloc_tx_channel_info failed, ret=%d", ret);
		goto out;
	}

	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_CDT_CONSUMED, 0);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_CDT_LIMIT, 0);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_COMP_CNT, 0);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_DESC_RAM_STATUS, 0);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_DM_CFG, 0);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_DM_STATUS, 0);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_WB_CFG,
			      SPP_H2C_WB_CFG_ALL_EN);

	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_STATUS_WB_ADDR_LO,
			      tx_chan->tx_info.tx_status_phys_addr &
			      SPP_H2C_STATUS_WB_ADDR_LO_MASK);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_STATUS_WB_ADDR_HI,
			      tx_chan->tx_info.tx_status_phys_addr >>
			      SPP_H2C_STATUS_WB_ADDR_HI_SHIFT);

	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_WC_TO_CNT,
			      SPP_H2C_WC_TO_CNT_ALL);

	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_WB_STATUS_ERR, 0);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_WB_STATUS, 0);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_BUF_CFG, 0);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_BUF_STATUS, 0);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_BUF_IN_PKT_CNT, 0);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_BUF_OUT_PKT_CNT, 0);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_BUF_PTR, 0);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_AUX_RAM_PTR, 0);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_BUF_ENTRIES, 0);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_DM_BUF_PTR, 0);

	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_AXIS_PKT_CNT, 0);


	/*
	 * spp_alloc_tx_channel_info has already cleared the tx_info write-back
	 * memzone.
	 */
	tx_chan->tx_info.tx_status->desc_limit = tx_chan->ring_size;
out:
	return ret;
}

static void
spp_free_tx_channel_sw_descs(struct spp_tx_channel *tx_chan)
{
	struct spp_sw_desc *sw_ring = tx_chan->sw_tx_info.sw_ring;
	struct rte_mbuf *mbuf;
	uint32_t i;

	for (i = 0; i < tx_chan->ring_size; i++) {
		struct spp_sw_desc *sw_desc = &sw_ring[i];

		mbuf = spp_consume_sw_desc(sw_desc);
		if (mbuf)
			/*
			 * rte_pktmbuf_free_seg handles the mbuf->next=NULL,
			 * and nb_segs=1
			 */
			rte_pktmbuf_free_seg(mbuf);
	}
}

static int
spp_destroy_tx_channel(struct spp_tx_channel *tx_chan)
{
	int ret = 0;

	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_CDT_CONSUMED, 0);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_CDT_LIMIT, 0);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_COMP_CNT, 0);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_DESC_RAM_STATUS, 0);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_DM_CFG, 0);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_DM_STATUS, 0);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_WB_CFG, 0);

	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_STATUS_WB_ADDR_LO, 0);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_STATUS_WB_ADDR_HI, 0);

	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_WC_TO_CNT, 0);

	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_WB_STATUS_ERR, 0);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_WB_STATUS, 0);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_BUF_CFG, 0);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_BUF_STATUS, 0);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_BUF_IN_PKT_CNT, 0);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_BUF_OUT_PKT_CNT, 0);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_BUF_PTR, 0);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_AUX_RAM_PTR, 0);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_BUF_ENTRIES, 0);
	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_DM_BUF_PTR, 0);

	spp_tx_chan_reg_write(tx_chan, SPP_REG_H2C_AXIS_PKT_CNT, 0);

	spp_free_tx_channel_sw_descs(tx_chan);

	if (tx_chan->tx_info.mem_zone) {
		ret = rte_memzone_free(tx_chan->tx_info.mem_zone);
		if (ret) {
			SPP_LOG(CRIT, "rte_memzone_free failed, ret=%d", ret);
			goto out;
		}
	}
out:
	return ret;
}

static inline int
spp_rx_pkt_get_read_last_seg(struct spp_rx_channel	*rx_chan,
			     uint16_t			*read_last_seg)
{
	struct spp_wb_meta_desc *wb_meta_ring = rx_chan->rx_info.wb_meta_ring;
	struct spp_wb_meta_desc *meta_desc;
	uint16_t read_tmp;
	int ret = -EBUSY;

	/*
	 * We already checked the first desc in the chain in spp_rx_pkt.
	 * Now check all subsequent descs in the chain for EOP.
	 */
	read_tmp = SPP_RING_IDX_NEXT(rx_chan->read, rx_chan->ring_size);
	meta_desc = &wb_meta_ring[read_tmp];

	while (meta_desc->valid_eop_bits & SPP_WB_META_DESC_VALID) {
		/*
		 * Ensure that the read pointer will not equal next_to_fill
		 * once the desc chain up to EOP is processed and the read
		 * pointer is incremented.
		 */
		if (unlikely(SPP_RING_IDX_NEXT(read_tmp, rx_chan->ring_size) ==
			     rx_chan->next_to_fill)) {
			SPP_LOG(DEBUG, "read_next_tmp==next_to_fill=%u",
				rx_chan->next_to_fill);
			break;
		}

		if (meta_desc->valid_eop_bits & SPP_WB_META_DESC_EOP) {
#if defined(SPP_DBG_USE_DESC_SEQ_NUM)
			spp_dbg_wb_desc_seq_num(rx_chan, meta_desc);
#endif
			*read_last_seg = read_tmp;
			ret = 0;
			break;
		}

		read_tmp = SPP_RING_IDX_NEXT(read_tmp, rx_chan->ring_size);
		meta_desc = &wb_meta_ring[read_tmp];
	}

	if (unlikely(ret))
		rx_chan->stats.no_last_seg++;
	else
		rx_chan->stats.seg_packets++;

	return ret;
}

static int
spp_rx_pkt(struct spp_rx_channel *rx_chan, struct rte_mbuf **rx_pkt)
{
	struct spp_wb_meta_desc *wb_meta_ring = rx_chan->rx_info.wb_meta_ring;
	struct spp_sw_desc *sw_ring = rx_chan->sw_rx_info.sw_ring;
	struct spp_wb_meta_desc *meta_desc;
	struct rte_mbuf *mbuf;
	uint16_t read = rx_chan->read;
	int ret = 0;

	/*
	 * Ensure that the read pointer will not equal next_to_fill
	 * once the desc (chain) up to EOP is processed and the read
	 * pointer is incremented.
	 */
	if (unlikely(SPP_RING_IDX_NEXT(read, rx_chan->ring_size) ==
		     rx_chan->next_to_fill)) {
		SPP_LOG(DEBUG, "read_next==next_to_fill=%u",
			rx_chan->next_to_fill);
		ret = -EBUSY;
		goto out;
	}

	meta_desc = &wb_meta_ring[read];
	RTE_ASSERT(meta_desc->valid_eop_bits & SPP_WB_META_DESC_VALID);

	if (likely(meta_desc->valid_eop_bits & SPP_WB_META_DESC_EOP)) {
		/* Single mbuf segment optimization */
		mbuf = spp_consume_sw_desc(&sw_ring[read]);
		if (unlikely(mbuf == NULL)) {
			SPP_LOG(ERR, "mbuf is NULL, read=%u", read);
			ret = -EBUSY;
			goto out;
		}
		mbuf->nb_segs = 1;
		mbuf->pkt_len = meta_desc->length;
		mbuf->data_len = mbuf->pkt_len;
		mbuf->data_off = RTE_PKTMBUF_HEADROOM;
		mbuf->port = rx_chan->spp_dev->dev_index;
		mbuf->ol_flags = 0;

#if defined(SPP_DBG_SW_LOOPBACK)
		spp_dbg_tx_rx_loopback_rx_cb(rx_chan);
#endif
#if defined(SPP_DBG_USE_DESC_SEQ_NUM)
		spp_dbg_wb_desc_seq_num(rx_chan, meta_desc);
#endif
#if defined(SPP_DBG_USE_MBUF_SEQ_NUM)
		spp_dbg_rx_pkt_seq_num(rx_chan, mbuf,
				       1, 1); /* sop==1, eop=1 */
#endif

		rx_chan->stats.bytes += mbuf->data_len;

		spp_meta_desc_memset(meta_desc);
		read = SPP_RING_IDX_NEXT(read, rx_chan->ring_size);
	} else {
		/* Multiple mbuf segments */
		struct rte_mbuf *mbuf_head = NULL;
		struct rte_mbuf *mbuf_tail;
		struct rte_mbuf *mbuf_tmp;
		uint16_t read_last_seg;

		ret = spp_rx_pkt_get_read_last_seg(rx_chan, &read_last_seg);
		if (unlikely(ret)) {
			SPP_LOG(DEBUG, "spp_rx_pkt_get_read_last_seg failed");
			goto out;
		}

		while (read !=
		       SPP_RING_IDX_NEXT(read_last_seg, rx_chan->ring_size)) {
			mbuf_tmp = spp_consume_sw_desc(&sw_ring[read]);
			if (unlikely(mbuf_tmp == NULL)) {
				SPP_LOG(ERR, "mbuf_tmp is NULL, read=%u", read);
				ret = -EBUSY;
				goto out;
			}

			if (mbuf_head == NULL) {
				mbuf_head = mbuf_tail = mbuf_tmp;
				mbuf_head->nb_segs = 1;
				mbuf_head->pkt_len = meta_desc->length;
			} else {
				mbuf_head->nb_segs++;
				mbuf_head->pkt_len += meta_desc->length;
				mbuf_tail->next = mbuf_tmp;
				mbuf_tail = mbuf_tmp;
			}

			mbuf_tmp->data_len = meta_desc->length;
			mbuf_tmp->data_off = RTE_PKTMBUF_HEADROOM;
			mbuf_tmp->port = rx_chan->spp_dev->dev_index;
			mbuf_tmp->ol_flags = 0;

#if defined(SPP_DBG_SW_LOOPBACK)
			spp_dbg_tx_rx_loopback_rx_cb(rx_chan);
#endif
#if defined(SPP_DBG_USE_MBUF_SEQ_NUM)
			/*
			 * sop: mbuf_head == mbuf_tail
			 * eop: read == read_last_seg
			 */
			spp_dbg_rx_pkt_seq_num(rx_chan, mbuf_tmp,
					       mbuf_head == mbuf_tail,
					       read == read_last_seg);
#endif

			rx_chan->stats.bytes += mbuf_tmp->data_len;

			spp_meta_desc_memset(meta_desc);
			read = SPP_RING_IDX_NEXT(read, rx_chan->ring_size);
			meta_desc = &wb_meta_ring[read];
		}

		mbuf = mbuf_head;
	}

	rx_chan->read = read;
	*rx_pkt = mbuf;
out:
	return ret;
}

static int
spp_clean_tx_channel(struct spp_tx_channel *tx_chan, uint16_t num_descs)
{
	int ret = 0;
	uint16_t next_to_clean = tx_chan->next_to_clean;
	struct spp_sw_desc *sw_ring = tx_chan->sw_tx_info.sw_ring;
	struct rte_mbuf *mbuf;
	int i;

	for (i = 0; i < num_descs; i++) {
		struct spp_sw_desc *sw_desc = &sw_ring[next_to_clean];

		mbuf = spp_consume_sw_desc(sw_desc);
		if (unlikely(mbuf == NULL)) {
			SPP_LOG(ERR, "mbuf is NULL, next_to_clean=%u",
				next_to_clean);
			spp_dbg_dump_tx_chan(tx_chan);
			ret = -EBUSY;
			goto out;
		}

		/*
		 * rte_pktmbuf_free_seg handles the mbuf->next=NULL,
		 * and nb_segs=1
		 */
		rte_pktmbuf_free_seg(mbuf);

		next_to_clean = SPP_RING_IDX_NEXT(next_to_clean,
						  tx_chan->ring_size);
	}

	tx_chan->next_to_clean = next_to_clean;
out:
	return ret;
}

static inline void
spp_tx_write_desc(struct spp_tx_channel *tx_chan, struct rte_mbuf *mbuf,
		  uint8_t eop)
{
	struct spp_tx_desc *tx_desc = tx_chan->tx_info.tx_desc;

#if defined(SPP_USE_COMPACT_DESCS)
	tx_desc->length = mbuf->data_len;
	tx_desc->phys_addr = (uint64_t)mbuf->buf_iova + mbuf->data_off;
	if (eop)
		tx_desc->phys_addr |= SPP_TX_DESC_EOP;
#else
	tx_desc->length = mbuf->data_len;
	tx_desc->phys_addr = (uint64_t)mbuf->buf_iova + mbuf->data_off;
	tx_desc->eop_spb_bits = (eop) ? SPP_TX_DESC_EOP : 0;

#if defined(SPP_DBG_USE_DESC_SEQ_NUM)
	if (eop)
		spp_dbg_tx_desc_seq_num(tx_chan, tx_desc);
#else
	tx_desc->user = 0;
#endif
#endif

	spp_tx_desc_memcpy(tx_chan->wc_mem + SPP_H2C_DESC_RAM_BASE,
			   (uint8_t *)tx_desc);

#if defined(SPP_DBG_DUMP_DESCS)
	spp_dbg_dump_tx_desc(tx_chan, tx_desc);
#endif
#if defined(SPP_DBG_SW_LOOPBACK)
	spp_dbg_tx_rx_loopback(tx_chan, tx_desc, mbuf);
#endif
}

static int
spp_tx_pkt(struct spp_tx_channel *tx_chan, struct rte_mbuf *tx_pkt)
{
	struct spp_sw_desc *sw_ring = tx_chan->sw_tx_info.sw_ring;
	struct spp_sw_desc *sw_desc;
	struct rte_mbuf *mbuf = tx_pkt;
	uint16_t write = tx_chan->write;
	uint16_t num_segs;
	uint16_t num_segs_tmp = 1;
	uint16_t tx_avail;
	uint8_t eop;
	int ret = 0;

	num_segs = mbuf->nb_segs;
	tx_avail = spp_tx_avail(tx_chan);
	if (unlikely(tx_avail < num_segs)) {
		tx_chan->stats.no_tx_avail++;
		SPP_LOG(DEBUG, "tx_avail(%u) < num_segs(%u)", tx_avail,
			num_segs);
		ret = -EBUSY;
		goto out;
	}

#if defined(SPP_DBG_USE_MBUF_SEQ_NUM)
	spp_dbg_tx_pkt_seq_num(tx_chan, mbuf,
			       1,                       /* sop==1 */
			       (mbuf->next) ? 0 : 1);   /* eop */
#endif

	sw_desc = &sw_ring[write];
	sw_desc->mbuf = mbuf;

	eop = (num_segs > 1) ? 0 : 1;
	spp_tx_write_desc(tx_chan, mbuf, eop);

	tx_chan->stats.bytes += mbuf->data_len;

	write = SPP_RING_IDX_NEXT(write, tx_chan->ring_size);
	mbuf = mbuf->next;
	while (mbuf) {
		/*
		 * We checked TX avail above.  Also check that
		 * that the mbuf seg list is not longer than
		 * specified in mbuf->nb_segs.
		 */
		if (unlikely(++num_segs_tmp > num_segs)) {
			SPP_LOG(ERR, "num_segs_tmp(%u) > num_segs(%u)",
				num_segs_tmp, num_segs);
			ret = -EINVAL;
			goto out;
		}

#if defined(SPP_DBG_USE_MBUF_SEQ_NUM)
		spp_dbg_tx_pkt_seq_num(tx_chan, mbuf,
				       0,                       /* sop==0 */
				       (mbuf->next) ? 0 : 1);   /* eop */
#endif

		sw_desc = &sw_ring[write];
		sw_desc->mbuf = mbuf;

		eop = (mbuf->next) ? 0 : 1;
		spp_tx_write_desc(tx_chan, mbuf, eop);

		tx_chan->stats.bytes += mbuf->data_len;

		write = SPP_RING_IDX_NEXT(write, tx_chan->ring_size);
		mbuf = mbuf->next;
	}

	/* Check that we processed all of the expected segs (EOP set) */
	if (unlikely(num_segs_tmp != num_segs)) {
		SPP_LOG(ERR, "num_segs_tmp(%u) != num_segs(%u)",
			num_segs_tmp, num_segs);
		ret = -EINVAL;
		goto out;
	}

	tx_chan->write = write;

	if (num_segs > 1)
		tx_chan->stats.seg_packets++;
out:
	return ret;
}

/******************************************************************************/
/******                             API                                   *****/
/******************************************************************************/

int
spp_rx_queue_setup(struct rte_eth_dev *eth_dev, uint16_t rx_queue_id,
		   uint16_t nb_rx_desc,
		   unsigned int socket_id,
		   const struct rte_eth_rxconf *rx_conf __rte_unused,
		   struct rte_mempool *mb_pool)
{
	struct spp_dev *spp_dev = (struct spp_dev *)eth_dev->data->dev_private;
	struct spp_rx_chan_cap *rx_chan_cap;
	struct spp_rx_channel *rx_chan;
	int ret = 0;

	if (!(spp_dev->dev_cap.flags & SPP_SDE_INFO_C2H_EN)) {
		SPP_LOG(ERR, "SDE C2H (RX) is not present");
		ret = -EINVAL;
		goto out;
	}
	if (rx_queue_id >= spp_dev->dev_cap.num_rx_channels) {
		SPP_LOG(ERR, "rx_queue_id is invalid (0 <= %u < %u)",
			rx_queue_id, spp_dev->dev_cap.num_rx_channels);
		ret = -EINVAL;
		goto out;
	}

	rx_chan_cap = &spp_dev->dev_cap.rx_chan_cap[rx_queue_id];

	if (!nb_rx_desc || (nb_rx_desc > rx_chan_cap->num_descs)) {
		SPP_LOG(ERR, "nb_desc is invalid (0 < %u <= %u)",
			nb_rx_desc, rx_chan_cap->num_descs);
		ret = -EINVAL;
		goto out;
	}
	if (!rte_is_power_of_2(nb_rx_desc)) {
		SPP_LOG(ERR,
			"Unsupported size of RX queue: %u is not a power of 2",
			nb_rx_desc);
		ret = -EINVAL;
		goto out;
	}

	rx_chan = &spp_dev->rx_channels[rx_queue_id];

	if (rx_chan->configured) {
		SPP_LOG(ERR, "API violation. Queue %u is already configured",
			rx_queue_id);
		ret = -EINVAL;
		goto out;
	}

	memset(rx_chan, 0, sizeof(*rx_chan));
	rx_chan->ring_size = nb_rx_desc;
	rx_chan->sw_rx_info.mb_pool = mb_pool;
	rx_chan->reg_mem = spp_dev->reg_mem;
	rx_chan->wc_mem = spp_dev->wc_mem;
	rx_chan->spp_dev = spp_dev;
	rx_chan->chan_index = rx_queue_id;

	ret = spp_init_rx_channel(rx_chan, socket_id);
	if (ret) {
		SPP_LOG(ERR, "spp_init_rx_channel failed, ret=%d", ret);
		goto out;
	}

	rx_chan->configured = SPP_CONF_SENTINAL;

	eth_dev->data->rx_queues[rx_queue_id] = rx_chan;
out:
	return ret;
}

void spp_rx_queue_release(void *q)
{
	struct spp_rx_channel *rx_chan = q;
	int ret;

	if (rx_chan) {
		ret = spp_destroy_rx_channel(rx_chan);
		if (ret)
			SPP_LOG(ERR, "spp_destroy_rx_channel failed, ret=%d",
				ret);
		/* Continue to clear the RX channel struct */

		memset(rx_chan, 0, sizeof(*rx_chan));
	}
}

int
spp_tx_queue_setup(struct rte_eth_dev *eth_dev, uint16_t tx_queue_id,
		   uint16_t nb_tx_desc,
		   __rte_unused unsigned int socket_id,
		   __rte_unused const struct rte_eth_txconf *tx_conf)
{
	struct spp_dev *spp_dev = (struct spp_dev *)eth_dev->data->dev_private;
	struct spp_tx_chan_cap *tx_chan_cap;
	struct spp_tx_channel *tx_chan;
	int ret = 0;

	if (!(spp_dev->dev_cap.flags & SPP_SDE_INFO_H2C_EN)) {
		SPP_LOG(ERR, "SDE H2C (TX) is not present");
		ret = -EINVAL;
		goto out;
	}
	if (tx_queue_id >= spp_dev->dev_cap.num_tx_channels) {
		SPP_LOG(ERR, "tx_queue_id is invalid (0 <= %u < %u)",
			tx_queue_id, spp_dev->dev_cap.num_tx_channels);
		ret = -EINVAL;
		goto out;
	}

	tx_chan_cap = &spp_dev->dev_cap.tx_chan_cap[tx_queue_id];

	if (!nb_tx_desc || (nb_tx_desc > tx_chan_cap->num_descs)) {
		SPP_LOG(ERR, "nb_desc is invalid (0 < %u <= %u)",
			nb_tx_desc, tx_chan_cap->num_descs);
		ret = -EINVAL;
		goto out;
	}
	if (!rte_is_power_of_2(nb_tx_desc)) {
		SPP_LOG(ERR,
			"Unsupported size of TX queue: %u is not a power of 2",
			nb_tx_desc);
		ret = -EINVAL;
		goto out;
	}

	tx_chan = &spp_dev->tx_channels[tx_queue_id];

	if (tx_chan->configured) {
		SPP_LOG(ERR, "API violation. Queue %u is already configured",
			tx_queue_id);
		ret = -EINVAL;
		goto out;
	}

	memset(tx_chan, 0, sizeof(*tx_chan));
	tx_chan->ring_size = nb_tx_desc;
	tx_chan->reg_mem = spp_dev->reg_mem;
	tx_chan->wc_mem = spp_dev->wc_mem;
	tx_chan->spp_dev = spp_dev;
	tx_chan->chan_index = tx_queue_id;

	ret = spp_init_tx_channel(tx_chan, socket_id);
	if (ret) {
		SPP_LOG(ERR, "spp_init_tx_channel failed, ret=%d", ret);
		goto out;
	}

	tx_chan->configured = SPP_CONF_SENTINAL;

	eth_dev->data->tx_queues[tx_queue_id] = tx_chan;
out:
	return ret;
}

void spp_tx_queue_release(void *q)
{
	struct spp_tx_channel *tx_chan = q;
	int ret;

	if (tx_chan) {
		ret = spp_destroy_tx_channel(tx_chan);
		if (ret)
			SPP_LOG(ERR, "spp_destroy_tx_channel failed, ret=%d",
				ret);
		/* Continue to clear the TX channel struct */

		memset(tx_chan, 0, sizeof(*tx_chan));
	}
}

uint16_t
spp_rx_pkt_burst(void *q, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	struct spp_rx_channel *rx_chan = q;
	struct spp_wb_meta_desc *wb_meta_ring = rx_chan->rx_info.wb_meta_ring;
	struct spp_wb_meta_desc *meta_desc;
	uint16_t nb_rx_pkts = 0;
	uint16_t num_descs;
	int ret = 0;

	while (nb_rx_pkts < nb_pkts) {
		uint16_t read = rx_chan->read;

		meta_desc = &wb_meta_ring[read];
		if (!meta_desc->valid_eop_bits & SPP_WB_META_DESC_VALID)
			break;

		ret = spp_rx_pkt(rx_chan, &rx_pkts[nb_rx_pkts]);
		if (unlikely(ret)) {
			/* spp_rx_pkt bumps the relevant error stat(s) */
			SPP_LOG(DEBUG, "spp_rx_pkt failed, ret=%d", ret);
			break;
		}

#if defined(SPP_USE_RING_THRESH)
		num_descs = spp_rx_descs_to_fill(rx_chan);
		if (num_descs >=
		    (rx_chan->ring_size >> SPP_RX_RING_FILL_SHIFT)) {
			ret = spp_fill_rx_channel(rx_chan, num_descs);
			if (unlikely(ret)) {
				SPP_LOG(ERR,
					"spp_fill_rx_channel failed, ret=%d",
					ret);
				goto out;
			}
		}
#endif

		nb_rx_pkts++;
	}

	num_descs = spp_rx_descs_to_fill(rx_chan);
	if (num_descs) {
		ret = spp_fill_rx_channel(rx_chan, num_descs);
		if (unlikely(ret)) {
			SPP_LOG(ERR, "spp_fill_rx_channel failed, ret=%d", ret);
			goto out;
		}
	}
out:
	ret = spp_rx_process_status(rx_chan);
	if (unlikely(ret)) {
		SPP_LOG(ERR, "spp_rx_process_status failed, ret=%d", ret);
		nb_rx_pkts = 0;
	}

	rx_chan->stats.packets += nb_rx_pkts;
	return nb_rx_pkts;
}

uint16_t
spp_tx_pkt_burst(void *q, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct spp_tx_channel *tx_chan = q;
	uint16_t nb_tx_pkts = 0;
	uint16_t num_descs;
	int ret;

	ret = spp_tx_process_status(tx_chan);
	if (unlikely(ret)) {
		SPP_LOG(ERR, "spp_tx_process_status failed, ret=%d", ret);
		goto out;
	}

	num_descs = spp_tx_descs_to_clean(tx_chan);
	if (num_descs) {
		ret = spp_clean_tx_channel(tx_chan, num_descs);
		if (unlikely(ret)) {
			SPP_LOG(ERR, "spp_clean_tx_channel failed, ret=%d",
				ret);
			ret = -EINVAL;
			goto out;
		}
	}

	while (nb_tx_pkts < nb_pkts) {
		ret = spp_tx_pkt(tx_chan, tx_pkts[nb_tx_pkts]);
		if (unlikely(ret)) {
			/* spp_tx_pkt bumps the relevant error stat(s) */
			SPP_LOG(DEBUG, "spp_tx_pkt failed, ret=%d", ret);
			break;
		}

#if defined(SPP_USE_RING_THRESH)
		num_descs = spp_tx_descs_to_clean(tx_chan);
		if (num_descs >=
		    (tx_chan->ring_size >> SPP_TX_RING_FILL_SHIFT)) {
			ret = spp_clean_tx_channel(tx_chan, num_descs);
			if (unlikely(ret)) {
				SPP_LOG(ERR,
					"spp_clean_tx_channel failed, ret=%d",
					ret);
				ret = -EINVAL;
				goto out;
			}
		}
#endif

		nb_tx_pkts++;
	}
out:
	tx_chan->stats.packets += nb_tx_pkts;
	return nb_tx_pkts;
}

int
spp_dev_reset(struct spp_dev *spp_dev)
{
#if !defined(SPP_DBG_SW_LOOPBACK)
	uint8_t *addr = spp_dev->reg_mem + SPP_REG_SDE_RESET;
	uint32_t value;
	int ret = 0;

	/* Check if the SDE is already in reset, or is returning all F's */
	value = rte_read32_relaxed(addr);
	if ((value & SPP_SDE_RESET_EN) != 0) {
		SPP_LOG(ERR,
			"already in reset: addr=%p, offset=0x%08x, value=0x%08x",
			addr, SPP_REG_SDE_RESET, value);
		ret = -EINVAL;
		goto out;
	}

	/* Reset the SDE and check that the reset took effect */
	value |= SPP_SDE_RESET_EN;
	rte_write32_relaxed(value, addr);

	value = rte_read32_relaxed(addr);
	if ((value & SPP_SDE_RESET_EN) != 1) {
		SPP_LOG(ERR,
			"reset enable failed: addr=%p, offset=0x%08x, value=0x%08x",
			addr, SPP_REG_SDE_RESET, value);
		ret = -EINVAL;
		goto out;
	}

	/* Bring the SDE out of reset */
	value &= ~SPP_SDE_RESET_EN;
	rte_write32_relaxed(value, addr);

	value = rte_read32_relaxed(addr);
	if ((value & SPP_SDE_RESET_EN) != 0) {
		SPP_LOG(ERR,
			"reset disable failed: addr=%p, offset=0x%08x, value=0x%08x",
			addr, SPP_REG_SDE_RESET, value);
		ret = -EINVAL;
		goto out;
	}

	SPP_LOG(DEBUG,
		"SDE reset completed: addr=%p, offset=0x%08x, value=0x%08x",
		addr, SPP_REG_SDE_RESET, value);

out:
	return ret;
#else
	(void)spp_dev;
	return 0;
#endif
}

int
spp_dev_cap_get(__rte_unused struct spp_dev	*spp_dev,
		struct spp_dev_cap		*dev_cap)
{
#if !defined(SPP_DBG_SW_LOOPBACK)
	uint8_t *addr;
	uint32_t value;
	int ret = 0;

	/* Zero out the device capabilities struct */
	memset(dev_cap, 0, sizeof(*dev_cap));

	/* Read the SDE Info */
	addr = spp_dev->reg_mem + SPP_REG_SDE_INFO;
	value = rte_read32_relaxed(addr);

	if ((value &
	     (SPP_SDE_INFO_C2H_EN | SPP_SDE_INFO_H2C_EN)) !=
	    (SPP_SDE_INFO_C2H_EN | SPP_SDE_INFO_H2C_EN)) {
		SPP_LOG(ERR,
			"SDE Info(0x%08x), c2h=%u, h2c=%u, is not supported",
			value,
			(value & SPP_SDE_INFO_C2H_EN) ? 1 : 0,
			(value & SPP_SDE_INFO_H2C_EN) ? 1 : 0);
		ret = -EINVAL;
		goto out;
	}

	SPP_LOG(DEBUG, "SDE Info(0x%08x), c2h=%u, h2c=%u",
		value,
		(value & SPP_SDE_INFO_C2H_EN) ? 1 : 0,
		(value & SPP_SDE_INFO_H2C_EN) ? 1 : 0);

	/* Setup the device capability flags */
	dev_cap->flags = value;

	/*
	 * Setup the number of RX and TX channels
	 *  -only one TX and RX channel is currently supported.
	 */
	dev_cap->num_rx_channels = 1;
	dev_cap->num_tx_channels = 1;

	/*
	 * Sanity check against max channels.
	 */
	if (dev_cap->num_rx_channels > SPP_RX_CHANNELS_MAX) {
		SPP_LOG(INFO,
			"num_rx_channels(%u) > SPP_RX_CHANNELS_MAX(%u), "
			"resetting to max value",
			dev_cap->num_rx_channels, SPP_RX_CHANNELS_MAX);
		dev_cap->num_rx_channels = SPP_RX_CHANNELS_MAX;
	}
	if (dev_cap->num_tx_channels > SPP_TX_CHANNELS_MAX) {
		SPP_LOG(INFO,
			"num_tx_channels(%u) > SPP_TX_CHANNELS_MAX(%u), "
			"resetting to max value",
			dev_cap->num_tx_channels, SPP_TX_CHANNELS_MAX);
		dev_cap->num_tx_channels = SPP_TX_CHANNELS_MAX;
	}

	/* RX Channel (C2H) */
	if (dev_cap->flags & SPP_SDE_INFO_C2H_EN) {
		addr = spp_dev->reg_mem + SPP_REG_C2H_DESC_INFO;
		value = rte_read32_relaxed(addr);

		SPP_LOG(INFO,
			"SDE C2H Desc Info(0x%08x), type=%s, num_descs=%u",
			value,
			(value & SPP_C2H_DESC_TYPE_COMPACT_EN) ?
			"compact" : "regular",
			(value >> SPP_C2H_DESC_RAM_DEPTH_SHIFT) &
			SPP_C2H_DESC_RAM_DEPTH_MASK);

#if defined(SPP_USE_COMPACT_DESCS)
		if (!(value & SPP_C2H_DESC_TYPE_COMPACT_EN)) {
			SPP_LOG(ERR, "SDE C2H Desc Info(0x%08x), "
				"type=regular, is not supported",
				value);
			ret = -EINVAL;
			goto out;
		}
#else
		if (value & SPP_C2H_DESC_TYPE_COMPACT_EN) {
			SPP_LOG(ERR, "SDE C2H Desc Info(0x%08x), "
				"type=compact, is not supported",
				value);
			ret = -EINVAL;
			goto out;
		}
#endif

		/* The SDE currently supports one RX channel */
		dev_cap->rx_chan_cap[0].flags =
			value & SPP_C2H_DESC_TYPE_COMPACT_EN;
		dev_cap->rx_chan_cap[0].num_descs =
			(value >> SPP_C2H_DESC_RAM_DEPTH_SHIFT) &
			SPP_C2H_DESC_RAM_DEPTH_MASK;
	}

	/* TX Channel (H2C) */
	if (dev_cap->flags & SPP_SDE_INFO_H2C_EN) {
		addr = spp_dev->reg_mem + SPP_REG_H2C_DESC_INFO;
		value = rte_read32_relaxed(addr);

		SPP_LOG(INFO,
			"SDE H2C Desc Info(0x%08x), type=%s, num_descs=%u",
			value,
			(value & SPP_H2C_DESC_TYPE_COMPACT_EN) ?
			"compact" : "regular",
			(value >> SPP_H2C_DESC_RAM_DEPTH_SHIFT) &
			SPP_H2C_DESC_RAM_DEPTH_MASK);

#if defined(SPP_USE_COMPACT_DESCS)
		if (!(value & SPP_H2C_DESC_TYPE_COMPACT_EN)) {
			SPP_LOG(ERR, "SDE H2C Desc Info(0x%08x), "
				"type=regular, is not supported",
				value);
			ret = -EINVAL;
			goto out;
		}
#else
		if (value & SPP_H2C_DESC_TYPE_COMPACT_EN) {
			SPP_LOG(ERR, "SDE H2C Desc Info(0x%08x), "
				"type=compact, is not supported",
				value);
			ret = -EINVAL;
			goto out;
		}
#endif

		/* The SDE currently supports one TX channel */
		dev_cap->tx_chan_cap[0].flags =
			value & SPP_H2C_DESC_TYPE_COMPACT_EN;
		dev_cap->tx_chan_cap[0].num_descs =
			(value >> SPP_H2C_DESC_RAM_DEPTH_SHIFT) &
			SPP_H2C_DESC_RAM_DEPTH_MASK;
	}

out:
	return ret;
#else
	dev_cap->flags = SPP_SDE_INFO_C2H_EN | SPP_SDE_INFO_H2C_EN;

#if defined(SPP_USE_COMPACT_DESCS)
	/* RX Channel (C2H) */
	dev_cap->rx_chan_cap[0].flags = SPP_C2H_DESC_TYPE_COMPACT_EN;
	dev_cap->rx_chan_cap[0].num_descs = SPP_RX_RING_DESC_MIN;

	/* TX Channel (H2C) */
	dev_cap->tx_chan_cap[0].flags = SPP_H2C_DESC_TYPE_COMPACT_EN;
	dev_cap->tx_chan_cap[0].num_descs = SPP_TX_RING_DESC_MIN;
#else
	/* RX Channel (C2H) */
	dev_cap->rx_chan_cap[0].flags = 0;
	dev_cap->rx_chan_cap[0].num_descs = SPP_RX_RING_DESC_MIN;

	/* TX Channel (H2C) */
	dev_cap->tx_chan_cap[0].flags = 0;
	dev_cap->tx_chan_cap[0].num_descs = SPP_TX_RING_DESC_MIN;
#endif

	dev_cap->num_rx_channels = 1;
	dev_cap->num_tx_channels = 1;
	return 0;
#endif
}

void
spp_dev_display(struct spp_dev *spp_dev)
{
	uint32_t i;

	for (i = 0; i < spp_dev->dev_cap.num_tx_channels; i++) {
		struct spp_tx_channel *tx_chan = &spp_dev->tx_channels[i];

		spp_dbg_dump_tx_chan(tx_chan);
	}
	for (i = 0; i < spp_dev->dev_cap.num_rx_channels; i++) {
		struct spp_rx_channel *rx_chan = &spp_dev->rx_channels[i];

		spp_dbg_dump_rx_chan(rx_chan);
	}
}
