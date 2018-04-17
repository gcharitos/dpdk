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

#ifndef _SPP_H_
#define _SPP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "spp_logs.h"
#include "spp_defs.h"
#include "spp_hal.h"

struct spp_dev {
	/* OS defined structs */
	struct rte_pci_device	*pci_dev;
	struct rte_eth_dev_data *rte_eth_dev_data;
	struct rte_eth_dev	*rte_eth_dev;

	struct spp_tx_channel	tx_channels[SPP_TX_CHANNELS_MAX]
	__rte_cache_aligned;
	struct spp_rx_channel	rx_channels[SPP_RX_CHANNELS_MAX]
	__rte_cache_aligned;

	uint8_t __iomem		*reg_mem;
	uint8_t __iomem		*wc_mem;

	int			dev_index;
	char			name[NAME_MAX + 1];
	struct ether_addr	ether_addr;
	struct spp_dev_cap	dev_cap;
};

#ifdef __cplusplus
}
#endif

#endif
