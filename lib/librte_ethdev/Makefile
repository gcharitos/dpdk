# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2017 Intel Corporation

export RTE_SDK=/home/centos/src/project_data/aws-fpga/sdk/apps/virtual-ethernet/scripts/ve_inst/dpdk
export RTE_TARGET=/home/centos/src/project_data/aws-fpga/sdk/apps/virtual-ethernet/scripts/ve_inst/dpdk/x86_64-native-linuxapp-gcc
export RTE_SDK_BIN=/home/centos/src/project_data/aws-fpga/sdk/apps/virtual-ethernet/scripts/ve_inst/dpdk/x86_64-native-linuxapp-gcc
include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
LIB = librte_ethdev.a

CFLAGS += -DALLOW_EXPERIMENTAL_API
#CFLAGS += -O3
CFLAGS += -O0 -g
CFLAGS += $(WERROR_FLAGS)
LDLIBS += -lrte_net -lrte_eal -lrte_mempool -lrte_ring
LDLIBS += -lrte_mbuf

EXPORT_MAP := rte_ethdev_version.map

LIBABIVER := 9

SRCS-y += rte_ethdev.c
SRCS-y += rte_flow.c
SRCS-y += rte_tm.c
SRCS-y += rte_mtr.c
SRCS-y += ethdev_profile.c

#
# Export include files
#
SYMLINK-y-include += rte_ethdev.h
SYMLINK-y-include += rte_ethdev_driver.h
SYMLINK-y-include += rte_ethdev_core.h
SYMLINK-y-include += rte_ethdev_pci.h
SYMLINK-y-include += rte_ethdev_vdev.h
SYMLINK-y-include += rte_eth_ctrl.h
SYMLINK-y-include += rte_dev_info.h
SYMLINK-y-include += rte_flow.h
SYMLINK-y-include += rte_flow_driver.h
SYMLINK-y-include += rte_tm.h
SYMLINK-y-include += rte_tm_driver.h
SYMLINK-y-include += rte_mtr.h
SYMLINK-y-include += rte_mtr_driver.h

include $(RTE_SDK)/mk/rte.lib.mk
