/*
 * Copyright (c) 2023 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tee_client_api.h>
#include "teep_agent_ta.h"
#include "tee_interface.h"

static bool to_hex(char *dest, size_t dest_len, const uint8_t *values,
                   size_t val_len)
{
    static const char hex_table[] = "0123456789ABCDEF";
    if (dest_len < (val_len * 2 + 1)) /* check that dest is large enough */
        return false;
    while (val_len--) {
        /* shift down the top nibble and pick a char from the hex_table */
        *dest++ = hex_table[*values >> 4];
        /* extract the bottom nibble and pick a char from the hex_table */
        *dest++ = hex_table[*values++ & 0xF];
    }
    *dest = 0;
    return true;
}

static void print_binary(const void *object, uint32_t size,
                         const char *object_name)
{
    size_t hexstr_size = size * sizeof(char) * 2 + 1;
    char *hexstr = (char *)malloc(hexstr_size);
    to_hex(hexstr, hexstr_size, object, size);
    printf("[%s(%d)] %s\n", object_name, size, hexstr);
    free(hexstr);
}

size_t invoke_teep_agent(const char *in_data1, size_t in_data_size1,
                         const char *in_data2, size_t in_data_size2,
                         char *out_data1, size_t *out_data_size1,
                         char *out_data2, size_t *out_data_size2,
                         uint32_t commandId)
{
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_TEEP_AGENT_UUID;
    uint32_t err_origin;

    /* ======================================== */
    /* Initialize a context connecting us to the TEE */
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
    }

    /*
     * Open a session
     */
    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL,
                           &err_origin);
    if (res != TEEC_SUCCESS) {
        errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x", res,
             err_origin);
    }

    /* ======================================== */
    /* Clear the TEEC_Operation struct */
    memset(&op, 0, sizeof(op));

    /* ======================================== */
    /* Prepare Sharedmemory                     */
    /* ======================================== */
    TEEC_SharedMemory shm1 = {};
    shm1.size = TEE_INTERFACE_STACK_BUF;
    shm1.flags = TEEC_MEM_OUTPUT;
    TEEC_AllocateSharedMemory(&ctx, &shm1);
    memset(shm1.buffer, 0, shm1.size);

    TEEC_SharedMemory shm2 = {};
    shm2.size = TEE_INTERFACE_STACK_BUF;
    shm2.flags = TEEC_MEM_OUTPUT;
    TEEC_AllocateSharedMemory(&ctx, &shm2);
    memset(shm2.buffer, 0, shm2.size);
    /*
     * Prepare the argument. Pass a value in the first parameter,
     * the remaining three parameters are unused.
     */
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
        TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_MEMREF_PARTIAL_OUTPUT);

    op.params[0].tmpref.buffer = (void *)in_data1;
    op.params[0].tmpref.size = in_data_size1;
    op.params[1].tmpref.buffer = (void *)in_data2;
    op.params[1].tmpref.size = in_data_size2;

    op.params[2].memref.parent = &shm1;
    op.params[2].memref.size = shm1.size;
    op.params[2].memref.offset = 0;

    op.params[3].memref.parent = &shm2;
    op.params[3].memref.size = shm2.size;
    op.params[3].memref.offset = 0;

    printf("\n[Broker -> Agent] (commandId: %d)\n", commandId);
    res = TEEC_InvokeCommand(&sess, commandId, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res,
             err_origin);
    }

    if (!op.params[1].tmpref.buffer) {
        err(1, "Cannot allocate out buffer of size %zu",
            op.params[1].tmpref.size);
    }

    memcpy(out_data1, op.params[2].memref.parent->buffer,
           op.params[2].memref.size);
    *out_data_size1 = op.params[2].memref.size;

    memcpy(out_data2, op.params[3].memref.parent->buffer,
           op.params[3].memref.size);
    *out_data_size2 = op.params[3].memref.size;

    TEEC_CloseSession(&sess);
    TEEC_ReleaseSharedMemory(&shm1);
    TEEC_ReleaseSharedMemory(&shm2);
    TEEC_FinalizeContext(&ctx);

    if (res == TEEC_SUCCESS) {
        return 0;
    } else {
        return 1;
    }
}
