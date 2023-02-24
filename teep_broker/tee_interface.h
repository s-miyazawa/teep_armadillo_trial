/*
 * Copyright (c) 2023 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _TEE_INTERFACE_H_
#define _TEE_INTERFACE_H_
#include <stdlib.h>
#include <stdint.h>

#define TEE_INTERFACE_STACK_BUF 1024

size_t invoke_teep_agent(const char *in_data1, size_t in_data_size1,
                         const char *in_data2, size_t in_data_size2,
                         char *out_data1, size_t *out_data_size1,
                         char *out_data2, size_t *out_data_size2,
                         uint32_t commandId);
#endif /* _TEE_INTERFACE_H_ */
