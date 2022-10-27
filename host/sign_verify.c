/*
 * Copyright (c) 2022 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 */
#include <err.h>
#include <stdio.h>
#include <string.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <teep_armadillo_trial_ta.h>

#include "sign_verify.h"

TEEC_Result es256sign(const char *data, size_t datasize)
{
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_TEEP_ARMADILLO_TRIAL_UUID;
    uint32_t err_origin;

    /* ======================================== */
    /* Initialize a context connecting us to the TEE */
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

    /*
     * Open a session 
     */
    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL,
                           &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x", res,
             err_origin);

    /* ======================================== */
    /* Clear the TEEC_Operation struct */
    memset(&op, 0, sizeof(op));

    /*
     * Prepare the argument. Pass a value in the first parameter,
     * the remaining three parameters are unused.
     */
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = (void *)data;
    op.params[0].tmpref.size = datasize;
    char buf[200] = {0};
    op.params[1].tmpref.buffer = buf;

    printf("Invoking TA to siging TEST\n");
    res = TEEC_InvokeCommand(&sess, TA_SIGN_ES256_CMD, &op, &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res,
             err_origin);

    if (!op.params[1].tmpref.buffer)
        err(1, "Cannot allocate out buffer of size %zu",
            op.params[1].tmpref.size);

    printf("Signed buffer: ");
    for (int n = 0; n < op.params[1].tmpref.size; n++)
        printf("%02x ", ((uint8_t *)op.params[1].tmpref.buffer)[n]);
    printf("\n");

    /* ======================================== */
    TEEC_CloseSession(&sess);

    TEEC_FinalizeContext(&ctx);

    return res;
}
