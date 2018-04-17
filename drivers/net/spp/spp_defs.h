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

#ifndef _SPP_DEFS_H_
#define _SPP_DEFS_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Enables use of SDE compact descriptors within the SPP
 * PMD at compile time.  For regular descriptors simply
 * ifdef-out the SPP_USE_COMPACT_DESCS define.
 *  -the SDE must also be built with compact descriptors
 *   enabled.  If there is a mismatch in configuration
 *   between SPP and the SDE, spp_dev_cap_get will return
 *   an error (-EINVAL).
 *  -also see spp_wb_meta_desc, spp_rx_desc and spp_tx_desc
 *   for the differences in descriptor fields and sizes.
 */
#if 0
#define SPP_USE_COMPACT_DESCS
#endif

#if defined(RTE_ARCH_X86) && defined(RTE_MACHINE_CPUFLAG_AVX2)
/*
 * Use AVX2 instructions for desc write-combining.
 */
#define SPP_USE_AVX2
#endif

/*
 * Non-default experimentation at the expense of max PPS.
 *   -cleaning the TX ring at a threshold within
 *    spp_tx_pkt_burst.
 *   -filling the RX ring at a threshold within
 *    spp_rx_pkt_burst.
 *
 * #define SPP_USE_RING_THRESH
 */

/*
 * HAL debug options:
 * #define SPP_DBG_USE_DESC_SEQ_NUM
 *	Useful in HW bringup.
 * #define SPP_DBG_USE_MBUF_SEQ_NUM
 *	Useful in HW bringup.
 *	Do not use for real traffic!
 * #define SPP_DBG_SW_LOOPBACK
 *	Measure and tune SW PPS w/o the HW.
 *	Go through the motions of TX/RX ring maintenance.
 *	Single mbuf segs only!
 *	~70MPPS aggregate TX/RX, single vCPU
 * #define SPP_DBG_DUMP_DESCS
 *      Useful in HW bringup.
 * #define SPP_DBG_XSTATS_DEV_DISPLAY
 *      Useful in HW bringup.
 *      Dump (log-info) the TX and RX status and descs when
 *      eth_spp_xstats_get is called.
 */

#if defined(SPP_USE_COMPACT_DESCS)
/* Compact descs do not have a user defined field */
#undef SPP_DBG_USE_DESC_SEQ_NUM
#endif

#define BIT(bit)                        (1 << (bit))
#define MIN(a, b)                       (((a) < (b)) ? (a) : (b))
#define SIZEOF_ARRAY(a)                 (size_t)(sizeof(a) / sizeof(a[0]))
#define ROUND_UP(n, d)                  (((n) + (d) - 1) & -(d))
#define DIV_ROUND_UP(n, d)              (((n) + (d) - 1) / (d))

#define SPP_RX_RING_DESC_MAX            (1 << 15)
#define SPP_RX_RING_DESC_MIN            (1 << 6)
#define SPP_RX_RING_DESC_ALIGN          SPP_RX_RING_DESC_MIN
#define SPP_TX_RING_DESC_MAX            (1 << 15)
#define SPP_TX_RING_DESC_MIN            (1 << 6)
#define SPP_TX_RING_DESC_ALIGN          SPP_TX_RING_DESC_MIN
#define SPP_RX_CHANNELS_MAX             RTE_PMD_RING_MAX_RX_RINGS
#define SPP_TX_CHANNELS_MAX             RTE_PMD_RING_MAX_TX_RINGS
#define SPP_RX_RING_FILL_SHIFT          1
#define SPP_TX_RING_FILL_SHIFT          1

/* Vendor ID used by Amazon devices */
#define PCI_VENDOR_ID_AMAZON          0x1d0f
/* Amazon devices */
#define PCI_DEVICE_ID_SDE_LOOPBACK_CL 0xf002

#define SPP_SDE_CTL_REGS_BAR    0
#define SPP_SDE_REGS_BAR        4
#define SPP_SDE_WC_BAR          4
#define SPP_SDE_WC_BAR_OFFSET   0
#define SPP_SDE_WC_BAR_SIZE     (1 << 16)

/** PCI device format string */
#define PCI_DEV_FMT "%04x:%02x:%02x.%d"

#define __iomem

#ifdef __cplusplus
}
#endif

#endif
