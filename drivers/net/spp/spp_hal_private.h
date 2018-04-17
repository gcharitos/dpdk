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

#ifndef _SPP_HAL_PRIVATE_H_
#define _SPP_HAL_PRIVATE_H_

#include "spp_logs.h"

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(SPP_DBG_SW_LOOPBACK)
#if defined(SPP_USE_AVX2)

#if defined(SPP_USE_COMPACT_DESCS)
/* Non-debug FastPath */
static inline void
spp_meta_desc_memset(void *buf)
{
	*(uint64_t *)buf = 0;
}

/**
 * Copy 16 bytes from one location to another,
 * locations should not overlap.
 */
static inline void
spp_rx_desc_memcpy(void *dst, const void *src)
{
	__m128i xmm0;

	xmm0 = _mm_loadu_si128((const __m128i *)src);
	_mm_storeu_si128((__m128i *)dst, xmm0);
}

/**
 * Copy 16 bytes from one location to another,
 * locations should not overlap.
 */
static inline void
spp_tx_desc_memcpy(void *dst, const void *src)
{
	__m128i xmm0;

	xmm0 = _mm_loadu_si128((const __m128i *)src);
	_mm_storeu_si128((__m128i *)dst, xmm0);
}
#else
/* Non-debug FastPath */
static inline void
spp_meta_desc_memset(void *buf)
{
	__m128i xmm0;

	xmm0 = _mm_setzero_si128();
	_mm_storeu_si128((__m128i *)buf, xmm0);
}

/**
 * Copy 16 bytes from one location to another,
 * locations should not overlap.
 */
static inline void
spp_rx_desc_memcpy(void *dst, const void *src)
{
	__m128i xmm0;

	xmm0 = _mm_loadu_si128((const __m128i *)src);
	_mm_storeu_si128((__m128i *)dst, xmm0);
}

/**
 * Copy 32 bytes from one location to another,
 * locations should not overlap.
 */
static inline void
spp_tx_desc_memcpy(void *dst, const void *src)
{
	__m256i ymm0;

	ymm0 = _mm256_loadu_si256((const __m256i *)src);
	_mm256_storeu_si256((__m256i *)dst, ymm0);
}
#endif

#else /* !SPP_USE_AVX2 */

static inline void
spp_meta_desc_memset(__rte_unused void *buf)
{
	SPP_LOG(ERR, "SPP_USE_AVX2 only is supported");
}

static inline void
spp_rx_desc_memcpy(__rte_unused void		*dst,
		   __rte_unused const void	*src)
{
	SPP_LOG(ERR, "SPP_USE_AVX2 only is supported");
}

static inline void
spp_tx_desc_memcpy(__rte_unused void		*dst,
		   __rte_unused const void	*src)
{
	SPP_LOG(ERR, "SPP_USE_AVX2 only is supported");
}
#endif /* SPP_USE_AVX2 */

static inline void
spp_tx_chan_reg_write(struct spp_tx_channel *tx_chan, uint32_t offset,
		      uint32_t value)
{
	uint8_t *addr = tx_chan->reg_mem + offset;

	rte_write32_relaxed(value, addr);
}

static inline uint32_t
spp_tx_chan_reg_read(struct spp_tx_channel *tx_chan, uint32_t offset)
{
	uint8_t *addr = tx_chan->reg_mem + offset;

	return rte_read32_relaxed(addr);
}

static inline void
spp_rx_chan_reg_write(struct spp_rx_channel *rx_chan, uint32_t offset,
		      uint32_t value)
{
	uint8_t *addr = rx_chan->reg_mem + offset;

	rte_write32_relaxed(value, addr);
}

static inline uint32_t
spp_rx_chan_reg_read(struct spp_rx_channel *rx_chan, uint32_t offset)
{
	uint8_t *addr = rx_chan->reg_mem + offset;

	return rte_read32_relaxed(addr);
}

#else

/* SW loopback mode, stubs out all MMIO */
static inline void
spp_meta_desc_memset(__rte_unused void *buf)
{
}

static inline void
spp_rx_desc_memcpy(__rte_unused void *dst, __rte_unused const void *src)
{
}

static inline void
spp_tx_desc_memcpy(__rte_unused void *dst, __rte_unused const void *src)
{
}

static inline void
spp_tx_chan_reg_write(__rte_unused struct spp_tx_channel *tx_chan,
		      __rte_unused uint32_t offset, __rte_unused
		      uint32_t value)
{
}

static inline uint32_t
spp_tx_chan_reg_read(__rte_unused struct spp_tx_channel *tx_chan,
		     __rte_unused uint32_t		offset)
{
	return -1;
}

static inline void
spp_rx_chan_reg_write(__rte_unused struct spp_rx_channel	*rx_chan,
		      __rte_unused uint32_t			offset,
		      __rte_unused uint32_t			value)
{
}

static inline uint32_t
spp_rx_chan_reg_read(__rte_unused struct spp_rx_channel *rx_chan,
		     __rte_unused uint32_t		offset)
{
	return -1;
}

int spp_dbg_tx_rx_loopback(struct spp_tx_channel *tx_chan,
			   struct spp_tx_desc *tx_desc, struct rte_mbuf *mbuf);

static inline void
spp_dbg_tx_rx_loopback_rx_cb(struct spp_rx_channel *rx_chan)
{
	struct spp_tx_channel *tx_chan;

	tx_chan = &rx_chan->spp_dev->tx_channels[rx_chan->chan_index];

	/*
	 * Bump the TX desc completed count.
	 *	-the RX desc limit is handled by TX processing
	 */
	tx_chan->tx_info.tx_status->desc_completed++;
}

#endif /* !SPP_DBG_SW_LOOPBACK */

static inline uint16_t
spp_tx_channel_get_read_desc_completed(struct spp_tx_channel *tx_chan)
{
	uint32_t read_desc_completed;

	read_desc_completed = tx_chan->tx_info.tx_status->desc_completed &
			      SPP_RING_MASK(tx_chan->ring_size);

	return read_desc_completed;
}

void spp_dbg_dump_rx_chan(struct spp_rx_channel *rx_chan);
void spp_dbg_dump_tx_chan(struct spp_tx_channel *tx_chan);

void spp_dbg_dump_rx_desc(struct spp_rx_channel *rx_chan,
			  struct spp_rx_desc	*rx_desc);
void spp_dbg_dump_tx_desc(struct spp_tx_channel *tx_chan,
			  struct spp_tx_desc	*tx_desc);

#if defined(SPP_DBG_USE_DESC_SEQ_NUM)
void spp_dbg_wb_desc_seq_num(struct spp_rx_channel	*rx_chan,
			     struct spp_wb_meta_desc	*meta_desc);
void spp_dbg_tx_desc_seq_num(struct spp_tx_channel	*tx_chan,
			     struct spp_tx_desc		*desc);
#endif

#if defined(SPP_DBG_USE_MBUF_SEQ_NUM)
void spp_dbg_tx_pkt_seq_num(struct spp_tx_channel *tx_chan,
			    struct rte_mbuf *mbuf, uint8_t sop, uint8_t eop);
void spp_dbg_rx_pkt_seq_num(struct spp_rx_channel *rx_chan,
			    struct rte_mbuf *mbuf, uint8_t sop, uint8_t eop);
#endif

#ifdef __cplusplus
}
#endif

#endif
