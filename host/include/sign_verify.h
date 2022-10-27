/*
 * Copyright (c) 2022 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef SIGN_VERIFY_H
#define SIGN_VERIFY_H

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

TEEC_Result es256sign(const char *data, size_t datasize);

#endif /* SIGN_VERIFY_H */
