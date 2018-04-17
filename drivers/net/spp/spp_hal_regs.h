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

#ifndef _SPP_HAL_REGS_H_
#define _SPP_HAL_REGS_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Register definitions
 */

/*
 * Register Base Addresses
 */

#define SPP_SDE_CTL_BASE        0x0
#define SPP_PCIS_BASE           0x0
#define SPP_C2H_DESC_RAM_BASE   0x0
#define SPP_H2C_DESC_RAM_BASE   0x1000
#define SPP_SPB_BASE            0x2000

#define SPP_CSR_PCIS_BASE       0x3000
#define SPP_CSR_PCIM_BASE       0x3200

#define SPP_CSR_C2H_GLOBAL_BASE 0x3400
#define SPP_CSR_C2H_DESC_BASE   0x3500
#define SPP_CSR_C2H_DATA_MOVER_BASE     0x3600
#define SPP_CSR_C2H_WB_BASE     0x3700
#define SPP_CSR_C2H_BUF_BASE    0x3800
#define SPP_CSR_C2H_AXIS_BASE   0x3900

#define SPP_CSR_H2C_GLOBAL_BASE 0x3a00
#define SPP_CSR_H2C_DESC_BASE   0x3b00
#define SPP_CSR_H2C_DATA_MOVER_BASE     0x3c00
#define SPP_CSR_H2C_WB_BASE     0x3d00
#define SPP_CSR_H2C_BUF_BASE    0x3e00
#define SPP_CSR_H2C_AXIS_BASE   0x3f00

/*
 * PCIS Registers
 */

#define SPP_REG_PCIS(offset)            (SPP_CSR_PCIS_BASE + (offset))
#define SPP_REG_SDE_RESET               SPP_REG_PCIS(0x0)

enum {
	SPP_SDE_RESET_EN = BIT(0),
};

#define SPP_REG_SDE_INFO                SPP_REG_PCIS(0x4)

enum {
	SPP_SDE_INFO_C2H_EN	= BIT(0),
	SPP_SDE_INFO_H2C_EN	= BIT(16),
};

/*
 * C2H Registers (SPP RX)
 */

#define SPP_REG_C2H_DESC(offset)        (SPP_CSR_C2H_DESC_BASE + (offset))
#define SPP_REG_C2H_CDT_CONSUMED        SPP_REG_C2H_DESC(0x0)
#define SPP_REG_C2H_CDT_LIMIT           SPP_REG_C2H_DESC(0x4)
#define SPP_REG_C2H_COMP_CNT            SPP_REG_C2H_DESC(0x8)
#define SPP_REG_C2H_DESC_FIFO           SPP_REG_C2H_DESC(0xc)

enum {
	SPP_C2H_DESC_FIFO_WRITE_MASK	= BIT(16) - 1,
	/* lower 16-bits */
	SPP_C2H_DESC_FIFO_READ_SHIFT	= BIT(16),
	/* upper 16-bits */
};

#define SPP_REG_C2H_DESC_RAM_ADDR       SPP_REG_C2H_DESC(0x10)
#define SPP_REG_C2H_DESC_RAM_DATA       SPP_REG_C2H_DESC(0x14)
#define SPP_REG_C2H_DESC_RAM_STATUS     SPP_REG_C2H_DESC(0x18)

enum {
	SPP_C2H_DESC_OFLOW_ERR		= BIT(0),
	/* Error: Desc written when desc RAM is full */
	SPP_C2H_DESC_OOO_ERR		= BIT(1),
	/* Error: Desc written out of order */
	SPP_C2H_DESC_UNALIGN_ERR	= BIT(2),
	/* Error: Desc unaligned address */
	SPP_C2H_DESC_FULL		= BIT(3),
	/* Status: Desc RAM full */
	SPP_C2H_DESC_EMPTY		= BIT(4),
	/* Status: Desc RAM empty */

	SPP_C2H_DESC_RAM_STATUS_ALL	=
		SPP_C2H_DESC_OFLOW_ERR |
		SPP_C2H_DESC_OOO_ERR |
		SPP_C2H_DESC_UNALIGN_ERR |
		SPP_C2H_DESC_FULL |
		SPP_C2H_DESC_EMPTY,
};

#define SPP_REG_C2H_DESC_INFO           SPP_REG_C2H_DESC(0x20)

enum {
	SPP_C2H_DESC_TYPE_COMPACT_EN	= BIT(0),

	SPP_C2H_DESC_RAM_DEPTH_MASK	= BIT(16) - 1,
	SPP_C2H_DESC_RAM_DEPTH_SHIFT	= 16,
};

#define SPP_REG_C2H_DATA_MOVER(offset)  (SPP_CSR_C2H_DATA_MOVER_BASE + (offset))
#define SPP_REG_C2H_DM_CFG              SPP_REG_C2H_DATA_MOVER(0x0)
#define SPP_REG_C2H_DM_STATUS           SPP_REG_C2H_DATA_MOVER(0x4)

enum {
	SPP_C2H_DM_BRESP_ERR	= BIT(0),
	/* Error: Bresp error */
	SPP_C2H_DM_DESC_LEN_ERR = BIT(1),
	/* Error: Desc length equal to zero */
};

#define SPP_REG_C2H_WB(offset)          (SPP_CSR_C2H_WB_BASE + (offset))
#define SPP_REG_C2H_WB_CFG              SPP_REG_C2H_WB(0x0)

enum {
	SPP_C2H_WB_CFG_DESC_CNT_EN		= BIT(0),
	SPP_C2H_WB_CFG_PKT_CNT_EN		= BIT(1),
	SPP_C2H_WB_CFG_CDT_EN			= BIT(2),
	SPP_C2H_WB_CFG_MD_RD_PTR_EN		= BIT(3),

	SPP_C2H_WB_CFG_DESC_CTD_WC_EN		= BIT(4),
	SPP_C2H_WB_CFG_DESC_CNT_WC_EN		= BIT(5),
	SPP_C2H_WB_CFG_PKT_CNT_WC_EN		= BIT(6),
	SPP_C2H_WB_CFG_MD_WR_PTR_WC_EN		= BIT(7),

	SPP_C2H_WB_CFG_WC_CNT_MINUS1_DFLT	= 0,
	SPP_C2H_WB_CFG_WC_CNT_MINUS1_MASK	= BIT(6) - 1,
	SPP_C2H_WB_CFG_WC_CNT_MINUS1_SHIFT	= 8,

	/* No C2H write-backs are enabled for PPS perf */
	SPP_C2H_WB_CFG_ALL_EN			= 0,
};

#define SPP_REG_C2H_STATUS_WB_ADDR_LO   SPP_REG_C2H_WB(0x4)
#define SPP_REG_C2H_STATUS_WB_ADDR_HI   SPP_REG_C2H_WB(0x8)

enum {
	SPP_C2H_STATUS_WB_ADDR_LO_MASK	= (1ULL << 32) - 1,
	/* lower 32-bits */
	SPP_C2H_STATUS_WB_ADDR_HI_SHIFT = 32,
	/* upper 32-bits */
};

#define SPP_REG_C2H_WC_TO_CNT           SPP_REG_C2H_WB(0xc)

enum {
	SPP_C2H_WC_TO_TICK_CNT_DFLT	= 0x4100,

	SPP_C2H_WC_TO_CNT_DFLT		= 0xf,
	SPP_C2H_WC_TO_CNT_MASK		= BIT(4) - 1,
	SPP_C2H_WC_TO_CNT_SHIFT		= 20,

	SPP_C2H_WC_TO_CNT_ALL		= 0,
};

#define SPP_REG_C2H_WB_META_RING_ADDR_LO        SPP_REG_C2H_WB(0x18)
#define SPP_REG_C2H_WB_META_RING_ADDR_HI        SPP_REG_C2H_WB(0x1c)

enum {
	SPP_C2H_WB_META_RING_ADDR_LO_MASK	= (1ULL << 32) - 1,
	/* lower 32-bits */
	SPP_C2H_WB_META_RING_ADDR_HI_SHIFT	= 32,
	/* upper 32-bits */
};

#define SPP_REG_C2H_WB_META_RING_SIZE   SPP_REG_C2H_WB(0x20)
#define SPP_REG_C2H_WB_META_RING_READ   SPP_REG_C2H_WB(0x24)

enum {
	SPP_C2H_WB_META_RING_READ_MASK = BIT(16) - 1,
	/* lower 16-bits */
};

#define SPP_REG_C2H_WB_META_RING_WRITE  SPP_REG_C2H_WB(0x28)

enum {
	SPP_C2H_WB_META_RING_WRITE_MASK = BIT(16) - 1,
	/* lower 16-bits */
};

#define SPP_REG_C2H_WB_STATUS_ERR       SPP_REG_C2H_WB(0x2c)

enum {
	SPP_C2H_WB_STATUS_BRESP_ERR	= BIT(0),
	/* Error: Status write-back Bresp error */
	SPP_C2H_WB_MD_BRESP_ERR		= BIT(1),
	/* Error: Metadata write-back Bresp error */
};

#define SPP_REG_C2H_WB_STATUS           SPP_REG_C2H_WB(0x30)

enum {
	SPP_C2H_STATUS_DESC_ERR = BIT(0),
	SPP_C2H_STATUS_DM_ERR	= BIT(1),
	SPP_C2H_STATUS_WB_ERR	= BIT(2),

	SPP_C2H_STATUS_ERR_ALL	=
		SPP_C2H_STATUS_DESC_ERR |
		SPP_C2H_STATUS_DM_ERR |
		SPP_C2H_STATUS_WB_ERR,
};

#define SPP_REG_C2H_BUF(offset)         (SPP_CSR_C2H_BUF_BASE + (offset))
#define SPP_REG_C2H_BUF_CFG             SPP_REG_C2H_BUF(0x0)
#define SPP_REG_C2H_BUF_STATUS          SPP_REG_C2H_BUF(0x4)

enum {
	SPP_C2H_BUF_FULL	= BIT(0),
	/* Status: Buffer full */
	SPP_C2H_BUF_EMPTY	= BIT(1),
	/* Status: Buffer empty */
	SPP_C2H_AXIS_FIFO_FULL	= BIT(2),
	/* Status: AXIS Fifo full */
	SPP_C2H_AXIS_FIFO_EMPTY = BIT(3),
	/* Status: AXIS Fifo empty */
};

#define SPP_REG_C2H_BUF_IN_PKT_CNT      SPP_REG_C2H_BUF(0x8)
#define SPP_REG_C2H_BUF_OUT_PKT_CNT     SPP_REG_C2H_BUF(0xc)
#define SPP_REG_C2H_BUF_PTR             SPP_REG_C2H_BUF(0x10)
#define SPP_REG_C2H_AUX_RAM_PTR         SPP_REG_C2H_BUF(0x14)
#define SPP_REG_C2H_BUF_NUM_BYTES       SPP_REG_C2H_BUF(0x18)

#define SPP_REG_C2H_AXIS(offset)        (SPP_CSR_C2H_AXIS_BASE + (offset))
#define SPP_REG_C2H_AXIS_PKT_CNT        SPP_REG_C2H_AXIS(0x0)

/*
 * H2C Registers (SPP TX)
 */

#define SPP_REG_H2C_DESC(offset)        (SPP_CSR_H2C_DESC_BASE + (offset))
#define SPP_REG_H2C_CDT_CONSUMED        SPP_REG_H2C_DESC(0x0)
#define SPP_REG_H2C_CDT_LIMIT           SPP_REG_H2C_DESC(0x4)
#define SPP_REG_H2C_COMP_CNT            SPP_REG_H2C_DESC(0x8)
#define SPP_REG_H2C_DESC_FIFO           SPP_REG_H2C_DESC(0xc)

enum {
	SPP_H2C_DESC_FIFO_WRITE_MASK	= BIT(16) - 1,
	/* lower 16-bits */
	SPP_H2C_DESC_FIFO_READ_SHIFT	= BIT(16),
	/* upper 16-bits */
};

#define SPP_REG_H2C_DESC_RAM_ADDR       SPP_REG_H2C_DESC(0x10)
#define SPP_REG_H2C_DESC_RAM_DATA       SPP_REG_H2C_DESC(0x14)
#define SPP_REG_H2C_DESC_RAM_STATUS     SPP_REG_H2C_DESC(0x18)

enum {
	SPP_H2C_DESC_OFLOW_ERR		= BIT(0),
	/* Error: Desc written when desc RAM is full */
	SPP_H2C_DESC_OOO_ERR		= BIT(1),
	/* Error: Desc written out of order */
	SPP_H2C_DESC_UNALIGN_ERR	= BIT(2),
	/* Error: Desc unaligned address */
	SPP_H2C_DESC_FULL		= BIT(3),
	/* Status: Desc RAM full */
	SPP_H2C_DESC_EMPTY		= BIT(4),
	/* Status: Desc RAM empty */
};

#define SPP_REG_H2C_DESC_INFO           SPP_REG_H2C_DESC(0x20)

enum {
	SPP_H2C_DESC_TYPE_COMPACT_EN	= BIT(0),

	SPP_H2C_DESC_RAM_DEPTH_MASK	= BIT(16) - 1,
	SPP_H2C_DESC_RAM_DEPTH_SHIFT	= 16,
};

#define SPP_REG_H2C_DATA_MOVER(offset)  (SPP_CSR_H2C_DATA_MOVER_BASE + (offset))
#define SPP_REG_H2C_DM_CFG              SPP_REG_H2C_DATA_MOVER(0x0)
#define SPP_REG_H2C_DM_STATUS           SPP_REG_H2C_DATA_MOVER(0x4)

enum {
	SPP_H2C_DM_RRESP_ERR	= BIT(0),
	/* Error: Rresp error */
	SPP_H2C_DM_DESC_LEN_ERR = BIT(1),
	/* Error: Desc length equal to zero */
};

#define SPP_REG_H2C_WB(offset)          (SPP_CSR_H2C_WB_BASE + (offset))
#define SPP_REG_H2C_WB_CFG              SPP_REG_H2C_WB(0x0)

enum {
	SPP_H2C_WB_CFG_DESC_CNT_EN		= BIT(0),
	SPP_H2C_WB_CFG_PKT_CNT_EN		= BIT(1),
	SPP_H2C_WB_CFG_CDT_EN			= BIT(2),

	SPP_H2C_WB_CFG_DESC_CTD_WC_EN		= BIT(4),
	SPP_H2C_WB_CFG_DESC_CNT_WC_EN		= BIT(5),
	SPP_H2C_WB_CFG_PKT_CNT_WC_EN		= BIT(6),

	SPP_H2C_WB_CFG_WC_CNT_MINUS1_DFLT	= 31,
	SPP_H2C_WB_CFG_WC_CNT_MINUS1_MASK	= BIT(6) - 1,
	SPP_H2C_WB_CFG_WC_CNT_MINUS1_SHIFT	= 8,

	SPP_H2C_WB_CFG_WC_ALL			=
		SPP_H2C_WB_CFG_DESC_CNT_WC_EN |
		((SPP_H2C_WB_CFG_WC_CNT_MINUS1_DFLT &
		  SPP_H2C_WB_CFG_WC_CNT_MINUS1_MASK) <<
		 SPP_H2C_WB_CFG_WC_CNT_MINUS1_SHIFT),

	/*
	 * SPP only uses the descriptor completed count and we want the
	 * write-back coalesced per the above configuration.
	 */
	SPP_H2C_WB_CFG_ALL_EN =
		SPP_H2C_WB_CFG_DESC_CNT_EN |
		SPP_H2C_WB_CFG_WC_ALL,
};

#define SPP_REG_H2C_STATUS_WB_ADDR_LO   SPP_REG_H2C_WB(0x4)
#define SPP_REG_H2C_STATUS_WB_ADDR_HI   SPP_REG_H2C_WB(0x8)

enum {
	SPP_H2C_STATUS_WB_ADDR_LO_MASK	= (1ULL << 32) - 1,
	/* lower 32-bits */
	SPP_H2C_STATUS_WB_ADDR_HI_SHIFT = 32,
	/* upper 32-bits */
};

#define SPP_REG_H2C_WC_TO_CNT           SPP_REG_H2C_WB(0xc)

enum {
	SPP_H2C_WC_TO_TICK_CNT_DFLT	= 0x4100,

	SPP_H2C_WC_TO_CNT_DFLT		= 0xf,
	SPP_H2C_WC_TO_CNT_MASK		= BIT(4) - 1,
	SPP_H2C_WC_TO_CNT_SHIFT		= 20,

	SPP_H2C_WC_TO_CNT_ALL		=
		SPP_H2C_WC_TO_TICK_CNT_DFLT |
		((SPP_H2C_WC_TO_CNT_DFLT &
		  SPP_H2C_WC_TO_CNT_MASK) <<
		 SPP_H2C_WC_TO_CNT_SHIFT),
};

#define SPP_REG_H2C_WB_STATUS_ERR       SPP_REG_H2C_WB(0x10)

enum {
	SPP_H2C_WB_STATUS_BRESP_ERR = BIT(0),
	/* Error: Status write-back Bresp error */
};

#define SPP_REG_H2C_WB_STATUS           SPP_REG_H2C_WB(0x14)

enum {
	SPP_H2C_STATUS_DESC_ERR = BIT(0),
	SPP_H2C_STATUS_DM_ERR	= BIT(1),
	SPP_H2C_STATUS_WB_ERR	= BIT(2),

	SPP_H2C_STATUS_ERR_ALL	=
		SPP_H2C_STATUS_DESC_ERR |
		SPP_H2C_STATUS_DM_ERR |
		SPP_H2C_STATUS_WB_ERR,
};

#define SPP_REG_H2C_BUF(offset)         (SPP_CSR_H2C_BUF_BASE + (offset))
#define SPP_REG_H2C_BUF_CFG             SPP_REG_H2C_BUF(0x0)
#define SPP_REG_H2C_BUF_STATUS          SPP_REG_H2C_BUF(0x4)

enum {
	SPP_H2C_BUF_FULL	= BIT(0),
	/* Status: Buffer full */
	SPP_H2C_BUF_EMPTY	= BIT(1),
	/* Status: Buffer empty */
	SPP_H2C_AXIS_FIFO_FULL	= BIT(2),
	/* Satus: AXIS Fifo full */
	SPP_H2C_AXIS_FIFO_EMPTY = BIT(3),
	/* Status: AXIS Fifo empty */
};

#define SPP_REG_H2C_BUF_IN_PKT_CNT      SPP_REG_H2C_BUF(0x8)
#define SPP_REG_H2C_BUF_OUT_PKT_CNT     SPP_REG_H2C_BUF(0xc)
#define SPP_REG_H2C_BUF_PTR             SPP_REG_H2C_BUF(0x10)
#define SPP_REG_H2C_AUX_RAM_PTR         SPP_REG_H2C_BUF(0x14)
#define SPP_REG_H2C_BUF_ENTRIES         SPP_REG_H2C_BUF(0x18)
#define SPP_REG_H2C_DM_BUF_PTR          SPP_REG_H2C_BUF(0x1c)

#define SPP_REG_H2C_AXIS(offset)        (SPP_CSR_H2C_AXIS_BASE + (offset))
#define SPP_REG_H2C_AXIS_PKT_CNT        SPP_REG_H2C_AXIS(0x0)

/*
 * Structure definitions for descriptors and write-back buffers
 */

#if defined(SPP_USE_COMPACT_DESCS)
/*
 * The SDE C2H desc (RX) is the same size for compact and regular.
 *  -note that the phys_addr is 48 bits for the compact desc.
 */
struct spp_rx_desc {
	uint32_t	length;
	uint64_t	phys_addr;
	uint32_t	reserved;
} __attribute__((packed));

/*
 * The SDE WB Meta desc (RX) is different for compact and regular.
 */
struct spp_wb_meta_desc {
	uint32_t	length;
	uint32_t	valid_eop_bits; /* see SPP_WB_META_DESC enum */
} __attribute__((packed));

enum {
	SPP_WB_META_DESC_VALID	= BIT(0),
	SPP_WB_META_DESC_EOP	= BIT(1),
};

/*
 * The SDE H2C desc (TX) is different for compact and regular.
 *  -note that the phys_addr is 48 bits for the compact desc.
 */
struct spp_tx_desc {
	uint32_t	length;
	uint64_t	phys_addr;
	/* The phys_addr is or'd with the EOP and SPB bits */
	uint32_t	reserved;
} __attribute__((packed));

enum {
	SPP_TX_DESC_EOP = 1ULL << 48,   /* > 32b shift */
	SPP_TX_DESC_SPB = 1ULL << 49,   /* > 32b shift */
};
#else
struct spp_rx_desc {
	uint32_t	length;
	uint64_t	phys_addr;
	uint32_t	reserved;
} __attribute__((packed));

struct spp_wb_meta_desc {
	uint32_t	length;
	uint32_t	valid_eop_bits; /* see SPP_WB_META_DESC enum */
	uint64_t	user;
} __attribute__((packed));

enum {
	SPP_WB_META_DESC_VALID	= BIT(0),
	SPP_WB_META_DESC_EOP	= BIT(1),
};

struct spp_tx_desc {
	uint32_t	length;
	uint64_t	phys_addr;
	uint32_t	eop_spb_bits; /* see SPP_TX_DESC enum */
	uint64_t	reserved;
	uint64_t	user;
} __attribute__((packed));

enum {
	SPP_TX_DESC_EOP = BIT(0),
	SPP_TX_DESC_SPB = BIT(1),
};
#endif

struct spp_rx_status {
	uint32_t	status; /* see SPP_RX_STATUS enum */
	uint32_t	desc_limit;
	uint32_t	desc_completed;
	uint32_t	pkt_count;
	uint32_t	meta_write;
} __attribute__((packed));

enum {
	SPP_RX_STATUS_DESC_ERR	= BIT(0),
	SPP_RX_STATUS_DM_ERR	= BIT(1),
	SPP_RX_STATUS_WB_ERR	= BIT(2),

	SPP_RX_STATUS_ERR_ALL	=
		SPP_RX_STATUS_DESC_ERR |
		SPP_RX_STATUS_DM_ERR |
		SPP_RX_STATUS_WB_ERR,
};

struct spp_tx_status {
	uint32_t	status; /* see SPP_TX_STATUS enum */
	uint32_t	desc_limit;
	uint32_t	desc_completed;
	uint32_t	pkt_count;
} __attribute__((packed));

enum {
	SPP_TX_STATUS_DESC_ERR	= BIT(0),
	SPP_TX_STATUS_DM_ERR	= BIT(1),
	SPP_TX_STATUS_WB_ERR	= BIT(2),

	SPP_TX_STATUS_ERR_ALL	=
		SPP_TX_STATUS_DESC_ERR |
		SPP_TX_STATUS_DM_ERR |
		SPP_TX_STATUS_WB_ERR,
};

#ifdef __cplusplus
}
#endif

#endif
