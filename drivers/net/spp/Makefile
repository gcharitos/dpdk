#
# Copyright 2015-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the
# License is located at
#
#     http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
#

export RTE_SDK=/home/centos/src/project_data/aws-fpga/sdk/apps/virtual-ethernet/scripts/ve_inst/dpdk
export RTE_TARGET=/home/centos/src/project_data/aws-fpga/sdk/apps/virtual-ethernet/scripts/ve_inst/dpdk/x86_64-native-linuxapp-gcc
export RTE_SDK_BIN=/home/centos/src/project_data/aws-fpga/sdk/apps/virtual-ethernet/scripts/ve_inst/dpdk/x86_64-native-linuxapp-gcc
include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
LIB = librte_pmd_spp.a
#CFLAGS += $(WERROR_FLAGS) -O2
CFLAGS += $(WERROR_FLAGS) -O0
CFLAGS += -g
INCLUDES :=-I$(SRCDIR)

EXPORT_MAP := rte_pmd_spp_version.map
LIBABIVER := 1

#
# all source are stored in SRCS-y
#
SRCS-$(CONFIG_RTE_LIBRTE_SPP_PMD) += spp_ethdev.c
SRCS-$(CONFIG_RTE_LIBRTE_SPP_PMD) += spp_hal.c
SRCS-$(CONFIG_RTE_LIBRTE_SPP_PMD) += spp_hal_dbg.c

CFLAGS += $(INCLUDES)
LDLIBS += -lrte_eal -lrte_mbuf -lrte_mempool -lrte_ring
LDLIBS += -lrte_ethdev -lrte_net -lrte_kvargs
LDLIBS += -lrte_bus_pci

include $(RTE_SDK)/mk/rte.lib.mk
