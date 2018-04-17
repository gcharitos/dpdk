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

void
spp_dbg_dump_rx_chan(struct spp_rx_channel *rx_chan)
{
	struct spp_rx_status *rx_status = rx_chan->rx_info.rx_status;
	uint32_t value;
	uint32_t i;

	/* General status info */
	SPP_LOG(INFO, "chan_index=%u, next_to_fill=%u, read=%u",
		rx_chan->chan_index, rx_chan->next_to_fill,
		rx_chan->read);
	SPP_LOG(INFO, "(status) chan_index=%u, status=0x%08x, desc_limit=%u, "
		"desc_completed=%u, pkt_count=%u, "
		"meta_write=%u",
		rx_chan->chan_index,
		rx_status->status, rx_status->desc_limit,
		rx_status->desc_completed, rx_status->pkt_count,
		rx_status->meta_write);

	/* Specific status info */
	if (rx_status->status & SPP_RX_STATUS_DESC_ERR) {
		value = spp_rx_chan_reg_read(rx_chan,
					     SPP_REG_C2H_DESC_RAM_STATUS);

		SPP_LOG(INFO,
			"SPP_RX_STATUS_DESC_ERR: oflow_err=%u, ooo_err=%u, unalign_err=%u, "
			"desc_full=%u, desc_empty=%u",
			(value & SPP_C2H_DESC_OFLOW_ERR) ? 1 : 0,
			(value & SPP_C2H_DESC_OOO_ERR) ? 1 : 0,
			(value & SPP_C2H_DESC_UNALIGN_ERR) ? 1 : 0,
			(value & SPP_C2H_DESC_FULL) ? 1 : 0,
			(value & SPP_C2H_DESC_EMPTY) ? 1 : 0);
	}
	if (rx_status->status & SPP_RX_STATUS_DM_ERR) {
		value = spp_rx_chan_reg_read(rx_chan, SPP_REG_C2H_DM_STATUS);

		SPP_LOG(INFO,
			"SPP_RX_STATUS_DM_ERR: bresp_err=%u, desc_len_err=%u",
			(value & SPP_C2H_DM_BRESP_ERR) ? 1 : 0,
			(value & SPP_C2H_DM_DESC_LEN_ERR) ? 1 : 0);
	}
	if (rx_status->status & SPP_RX_STATUS_WB_ERR) {
		value =
			spp_rx_chan_reg_read(rx_chan,
					     SPP_REG_C2H_WB_STATUS_ERR);

		SPP_LOG(INFO,
			"SPP_RX_STATUS_WB_ERR: status_bresp_err=%u, md_bresp_err=%u",
			(value & SPP_C2H_WB_STATUS_BRESP_ERR) ? 1 : 0,
			(value & SPP_C2H_WB_MD_BRESP_ERR) ? 1 : 0);
	}

	/* Dump the HW metadata and SW desc rings */
	for (i = 0; i < rx_chan->ring_size; i++) {
		struct spp_wb_meta_desc *meta_desc =
			&rx_chan->rx_info.wb_meta_ring[i];
		struct spp_sw_desc *sw_desc =
			&rx_chan->sw_rx_info.sw_ring[i];

#if defined(SPP_USE_COMPACT_DESCS)
		SPP_LOG(INFO, "chan_index=%02u, desc_index=%02u, "
			"meta_valid=%u, eop=%u, "
			"length=%u, "
			"sw_desc_valid=%u, nb_segs=%u, "
			"desc_buf_len=%u",
			rx_chan->chan_index, i,
			(meta_desc->valid_eop_bits &
			 SPP_WB_META_DESC_VALID) ? 1 : 0,
			(meta_desc->valid_eop_bits &
			 SPP_WB_META_DESC_EOP) ? 1 : 0,
			meta_desc->length,
			(sw_desc->mbuf) ? 1 : 0,
			(sw_desc->mbuf) ? sw_desc->mbuf->nb_segs : 0,
			(sw_desc->mbuf) ? sw_desc->mbuf->buf_len -
			RTE_PKTMBUF_HEADROOM : 0);
#else
		SPP_LOG(INFO, "chan_index=%02u, desc_index=%02u, "
			"meta_valid=%u, eop=%u, "
			"length=%u, user=%" PRIu64 ", "
			"sw_desc_valid=%u, nb_segs=%u, "
			"desc_buf_len=%u",
			rx_chan->chan_index, i,
			(meta_desc->valid_eop_bits &
			 SPP_WB_META_DESC_VALID) ? 1 : 0,
			(meta_desc->valid_eop_bits &
			 SPP_WB_META_DESC_EOP) ? 1 : 0,
			meta_desc->length, meta_desc->user,
			(sw_desc->mbuf) ? 1 : 0,
			(sw_desc->mbuf) ? sw_desc->mbuf->nb_segs : 0,
			(sw_desc->mbuf) ? sw_desc->mbuf->buf_len -
			RTE_PKTMBUF_HEADROOM : 0);
#endif
	}
}

void
spp_dbg_dump_tx_chan(struct spp_tx_channel *tx_chan)
{
	struct spp_tx_status *tx_status = tx_chan->tx_info.tx_status;
	uint32_t value;
	uint32_t i;

	/* General status info */
	SPP_LOG(INFO, "chan_index=%u, next_to_clean=%u, "
		"read_desc_completed=%u, write=%u",
		tx_chan->chan_index, tx_chan->next_to_clean,
		spp_tx_channel_get_read_desc_completed(
			tx_chan),
		tx_chan->write);
	SPP_LOG(INFO, "(status) chan_index=%u, status=0x%08x, desc_limit=%u, "
		"desc_completed=%u, pkt_count=%u",
		tx_chan->chan_index, tx_status->status,
		tx_status->desc_limit,
		tx_status->desc_completed, tx_status->pkt_count);

	/* Specific status info */
	if (tx_status->status & SPP_RX_STATUS_DESC_ERR) {
		value = spp_tx_chan_reg_read(tx_chan,
					     SPP_REG_H2C_DESC_RAM_STATUS);

		SPP_LOG(INFO,
			"SPP_RX_STATUS_DESC_ERR: oflow_err=%u, ooo_err=%u, unalign_err=%u, "
			"desc_full=%u, desc_empty=%u",
			(value & SPP_H2C_DESC_OFLOW_ERR) ? 1 : 0,
			(value & SPP_H2C_DESC_OOO_ERR) ? 1 : 0,
			(value & SPP_H2C_DESC_UNALIGN_ERR) ? 1 : 0,
			(value & SPP_H2C_DESC_FULL) ? 1 : 0,
			(value & SPP_H2C_DESC_EMPTY) ? 1 : 0);
	}
	if (tx_status->status & SPP_RX_STATUS_DM_ERR) {
		value = spp_tx_chan_reg_read(tx_chan, SPP_REG_H2C_DM_STATUS);

		SPP_LOG(INFO,
			"SPP_RX_STATUS_DM_ERR: rresp_err=%u, desc_len_err=%u",
			(value & SPP_H2C_DM_RRESP_ERR) ? 1 : 0,
			(value & SPP_H2C_DM_DESC_LEN_ERR) ? 1 : 0);
	}
	if (tx_status->status & SPP_RX_STATUS_WB_ERR) {
		value =
			spp_tx_chan_reg_read(tx_chan,
					     SPP_REG_H2C_WB_STATUS_ERR);

		SPP_LOG(INFO, "SPP_RX_STATUS_WB_ERR: bresp_err=%u",
			(value & SPP_H2C_WB_STATUS_BRESP_ERR) ? 1 : 0);
	}

	/* Dump the SW desc ring */
	for (i = 0; i < tx_chan->ring_size; i++) {
		struct spp_sw_desc *sw_desc =
			&tx_chan->sw_tx_info.sw_ring[i];

		SPP_LOG(INFO, "chan_index=%02u, desc_index=%02u, "
			"valid=%u, nb_segs=%u, data_len=%u",
			tx_chan->chan_index, i,
			(sw_desc->mbuf) ? 1 : 0,
			(sw_desc->mbuf) ? sw_desc->mbuf->nb_segs : 0,
			(sw_desc->mbuf) ? sw_desc->mbuf->data_len : 0);
	}
}

void
spp_dbg_dump_rx_desc(struct spp_rx_channel	*rx_chan,
		     struct spp_rx_desc		*rx_desc)
{
	spp_dbg_dump_rx_chan(rx_chan);
	SPP_LOG(INFO, "length=%u, phys_addr=0x%" PRIx64 ", reserved=0x%08x",
		rx_desc->length, rx_desc->phys_addr,
		rx_desc->reserved);
}

void
spp_dbg_dump_tx_desc(struct spp_tx_channel	*tx_chan,
		     struct spp_tx_desc		*tx_desc)
{
	spp_dbg_dump_tx_chan(tx_chan);
#if defined(SPP_USE_COMPACT_DESCS)
	SPP_LOG(INFO, "length=%u, phys_addr=0x%" PRIx64 ", eop=%u, spb=%u, "
		"reserved=0x%08x",
		tx_desc->length, tx_desc->phys_addr,
		(tx_desc->phys_addr & SPP_TX_DESC_EOP) ? 1 : 0,
		(tx_desc->phys_addr & SPP_TX_DESC_SPB) ? 1 : 0,
		tx_desc->reserved);
#else
	SPP_LOG(INFO, "length=%u, phys_addr=0x%" PRIx64 ", eop_spb_bits=%u, "
		"reserved=0x%" PRIx64 ", user=%" PRIu64,
		tx_desc->length, tx_desc->phys_addr,
		tx_desc->eop_spb_bits, tx_desc->reserved, tx_desc->user);
#endif
}

#if defined(SPP_DBG_USE_DESC_SEQ_NUM)
void
spp_dbg_wb_desc_seq_num(struct spp_rx_channel	*rx_chan,
			struct spp_wb_meta_desc *meta_desc)
{
	if (unlikely(meta_desc->user != rx_chan->desc_seq_num)) {
		SPP_LOG(ERR, "RX desc seq_num=%" PRIu64
			" != rx_chan_desc_seq_num=%" PRIu64,
			meta_desc->user, rx_chan->desc_seq_num);
	}
	rx_chan->desc_seq_num++;
}

void
spp_dbg_tx_desc_seq_num(struct spp_tx_channel	*tx_chan,
			struct spp_tx_desc	*desc)
{
	desc->user = tx_chan->desc_seq_num;
	tx_chan->desc_seq_num++;
}
#endif

#if defined(SPP_DBG_USE_MBUF_SEQ_NUM)
void
spp_dbg_rx_pkt_seq_num(struct spp_rx_channel *rx_chan, struct rte_mbuf *mbuf,
		       uint8_t sop, uint8_t eop)
{
	uint64_t *seq_num;
	uint32_t num_bytes = 0;

	if (sop) {
		num_bytes += sizeof(*seq_num);
		if (mbuf->data_len < num_bytes) {
			SPP_LOG(ERR, "(HDR) tailroom=%u < %u too small, "
				"sop=%u, eop=%u",
				mbuf->data_len,
				num_bytes,
				sop, eop);
			return;
		}
		seq_num =
			(uint64_t *)(((uint8_t *)mbuf->buf_addr) +
				     mbuf->data_off);
		if (!rte_is_aligned(seq_num, sizeof(*seq_num))) {
			SPP_LOG(ERR, "(HDR) RX mbuf seq_num=%p is not aligned, "
				"sop=%u, eop=%u",
				seq_num, sop, eop);
			return;
		}
		if (unlikely(*seq_num != rx_chan->mbuf_seq_num)) {
			SPP_LOG(ERR, "(HDR) RX mbuf seq_num=%" PRIu64
				" != rx_chan_mbuf_seq_num=%" PRIu64
				", sop=%u, eop=%u",
				*seq_num, rx_chan->mbuf_seq_num,
				sop, eop);
			return;
		}
	}

	if (eop) {
		num_bytes += sizeof(*seq_num);
		if (mbuf->data_len < num_bytes) {
			SPP_LOG(ERR, "(TRAILER) data_len=%u < %u too small, "
				"sop=%u, eop=%u",
				mbuf->data_len,
				num_bytes,
				sop, eop);
			return;
		}

		seq_num =
			(uint64_t *)(((uint8_t *)mbuf->buf_addr) +
				     mbuf->data_off +
				     mbuf->data_len - sizeof(uint64_t));
		if (!rte_is_aligned(seq_num, sizeof(*seq_num))) {
			SPP_LOG(ERR,
				"(TRAILER) RX mbuf seq_num=%p is not aligned, "
				"sop=%u, eop=%u",
				seq_num, sop,
				eop);
			return;
		}
		if (unlikely(*seq_num != rx_chan->mbuf_seq_num)) {
			SPP_LOG(ERR, "(TRAILER) RX mbuf seq_num=%" PRIu64
				" != rx_chan_mbuf_seq_num=%" PRIu64
				", sop=%u, eop=%u",
				*seq_num, rx_chan->mbuf_seq_num,
				sop, eop);
			return;
		}

		rx_chan->mbuf_seq_num++;
	}
}

void
spp_dbg_tx_pkt_seq_num(struct spp_tx_channel *tx_chan, struct rte_mbuf *mbuf,
		       uint8_t sop, uint8_t eop)
{
	uint64_t *seq_num;
	uint32_t num_bytes = 0;

	if (sop) {
		num_bytes += sizeof(*seq_num);
		if (mbuf->data_len < num_bytes) {
			SPP_LOG(ERR, "(HDR) data_len=%u < %u too small, "
				"sop=%u, eop=%u",
				mbuf->data_len,
				num_bytes,
				sop, eop);
			return;
		}
		seq_num =
			(uint64_t *)(((uint8_t *)mbuf->buf_addr) +
				     mbuf->data_off);
		if (!rte_is_aligned(seq_num, sizeof(*seq_num))) {
			SPP_LOG(ERR, "(HDR) RX mbuf seq_num=%p is not aligned, "
				"sop=%u, eop=%u",
				seq_num, sop, eop);
			return;
		}
		*seq_num = tx_chan->mbuf_seq_num;
	}

	if (eop) {
		num_bytes += sizeof(*seq_num);
		if (mbuf->data_len < num_bytes) {
			SPP_LOG(ERR, "(TRAILER) data_len=%u < %u too small, "
				"sop=%u, eop=%u",
				mbuf->data_len,
				num_bytes,
				sop, eop);
			return;
		}

		seq_num =
			(uint64_t *)(((uint8_t *)mbuf->buf_addr) +
				     mbuf->data_off +
				     mbuf->data_len - sizeof(*seq_num));
		if (!rte_is_aligned(seq_num, sizeof(*seq_num))) {
			SPP_LOG(ERR,
				"(TRAILER) RX mbuf seq_num=%p is not aligned, "
				"sop=%u, eop=%u",
				seq_num, sop,
				eop);
			return;
		}
		*seq_num = tx_chan->mbuf_seq_num;

		tx_chan->mbuf_seq_num++;
	}
}
#endif

#if defined(SPP_DBG_SW_LOOPBACK)
int spp_dbg_tx_rx_loopback(struct spp_tx_channel	*tx_chan,
			   struct spp_tx_desc		*tx_desc,
			   struct rte_mbuf		*tx_mbuf)
{
	struct spp_rx_channel *rx_chan;
	struct spp_wb_meta_desc *rx_meta_desc;
	uint16_t rx_chan_read;
	int ret = 0;

	/* Simulate the HW by looping TX back to RX */
	rx_chan = &tx_chan->spp_dev->rx_channels[tx_chan->chan_index];

	/* Get the current RX read index */
	rx_chan_read = rx_chan->rx_info.rx_status->desc_limit &
		       SPP_RING_MASK(rx_chan->ring_size);

#if 0
	{
		/*
		 * Swap TX and RX mbufs for zero copy loopback.
		 *      -we're using the rx_chan_read for both the TX and RX
		 *       sw_rings since in loopback mode, both rings move
		 *       together at the same rate.
		 */
		struct rte_mbuf *tmp_mbuf;
		tmp_mbuf = rx_chan->sw_rx_info.sw_ring[rx_chan_read].mbuf;
		rx_chan->sw_rx_info.sw_ring[rx_chan_read].mbuf = tx_mbuf;
		tx_chan->sw_tx_info.sw_ring[rx_chan_read].mbuf = tmp_mbuf;
	}
#else
#if defined(SPP_DBG_USE_MBUF_SEQ_NUM)
	{
		struct rte_mbuf *rx_mbuf;
		uint64_t *rx_seq_num;
		uint64_t *tx_seq_num;

		/* Transfer the debug sequence number from TX to RX */
		rx_mbuf = rx_chan->sw_rx_info.sw_ring[rx_chan_read].mbuf;

		tx_seq_num =
			(uint64_t *)(((uint8_t *)tx_mbuf->buf_addr) +
				     tx_mbuf->data_off);
		rx_seq_num =
			(uint64_t *)(((uint8_t *)rx_mbuf->buf_addr) +
				     rx_mbuf->data_off);
		*rx_seq_num = *tx_seq_num;
		SPP_LOG(DEBUG, "rx_seq_num=%" PRIu64, *rx_seq_num);
	}
#endif
#endif

	/* Fill in the RX meta desc */
	rx_meta_desc = &rx_chan->rx_info.wb_meta_ring[rx_chan_read];
	rx_meta_desc->length = tx_mbuf->data_len;
#if defined(SPP_USE_COMPACT_DESCS)
	if (likely(tx_desc->phys_addr & SPP_TX_DESC_EOP))
		rx_meta_desc->valid_eop_bits = SPP_WB_META_DESC_VALID |
					       SPP_WB_META_DESC_EOP;
	else
		rx_meta_desc->valid_eop_bits = SPP_WB_META_DESC_VALID;
#else
	if (likely(tx_desc->eop_spb_bits & SPP_TX_DESC_EOP))
		rx_meta_desc->valid_eop_bits = SPP_WB_META_DESC_VALID |
					       SPP_WB_META_DESC_EOP;
	else
		rx_meta_desc->valid_eop_bits = SPP_WB_META_DESC_VALID;
#endif

#if defined(SPP_DBG_USE_DESC_SEQ_NUM)
	rx_meta_desc->user = tx_desc->user;
#endif

	/*
	 * Bump the RX desc limit.  The TX desc limit is handled by RX
	 * processing
	 */
	rx_chan->rx_info.rx_status->desc_limit++;

	return ret;
}
#endif  /* SPP_DBG_SW_LOOPBACK */
