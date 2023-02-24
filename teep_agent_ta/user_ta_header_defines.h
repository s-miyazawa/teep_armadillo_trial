/*
 * Copyright (c) 2023 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The name of this file must not be modified (for OP-TEE SDK)
 */
#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

/* To get the TA UUID definition */
#include <teep_agent_ta.h>

#define TA_UUID TA_TEEP_AGENT_UUID

/*
 * TA properties: multi-instance TA, no specific attribute
 * TA_FLAG_EXEC_DDR is meaningless but mandated.
 */
#define TA_FLAGS TA_FLAG_EXEC_DDR

/* Provisioned stack size */
#define TA_STACK_SIZE (8 * 1024)

/* Provisioned heap size for TEE_Malloc() and friends */
#define TA_DATA_SIZE (32 * 1024)

/* The gpd.ta.version property */
#define TA_VERSION "1.0"

/* The gpd.ta.description property */
#define TA_DESCRIPTION "Proof of Concept Program for TEEP device"

#endif /* USER_TA_HEADER_DEFINES_H */
