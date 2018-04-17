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

#ifndef _SPP_LOGS_H_
#define _SPP_LOGS_H_

#define RTE_LOGTYPE_SPP RTE_LOGTYPE_USER1

#define SPP_LOG(level, fmt, args ...) \
	RTE_LOG(level, PMD, "%s(): " fmt "\n", __func__, ## args)

#define SPP_INIT_LOG(level, fmt, args ...) \
	RTE_LOG(level, PMD, "%s(): " fmt "\n", __func__, ## args)

#ifdef RTE_LIBRTE_SPP_DEBUG_RX
#define SPP_RX_LOG(level, fmt, args ...) \
	RTE_LOG(level, PMD, "%s(): " fmt "\n", __func__, ## args)
#else
#define SPP_RX_LOG(level, fmt, args ...) do { } while (0)
#endif

#ifdef RTE_LIBRTE_SPP_DEBUG_TX
#define SPP_TX_LOG(level, fmt, args ...) \
	RTE_LOG(level, PMD, "%s(): " fmt "\n", __func__, ## args)
#else
#define SPP_TX_LOG(level, fmt, args ...) do { } while (0)
#endif

#ifdef RTE_LIBRTE_SPP_DEBUG_DRIVER
#define SPP_DRV_LOG(level, fmt, args ...) \
	RTE_LOG(level, PMD, "%s(): " fmt "\n", __func__, ## args)
#else
#define SPP_DRV_LOG(level, fmt, args ...) do { } while (0)
#endif

#endif /* _SPP_LOGS_H_ */
