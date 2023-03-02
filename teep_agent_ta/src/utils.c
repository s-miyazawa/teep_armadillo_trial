/*
 * Copyright (c) 2023 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <qcbor/UsefulBuf.h>
#include <qcbor/qcbor_encode.h>
#include <teep/teep_common.h>
#include <teep/teep_message_data.h>

#include "teep_agent/utils.h"
#include <tee_api.h>
#include "teep_agent/api.h"

bool teep_agent_sign(UsefulBuf *workbuf, UsefulBufC *sign_target,
                     UsefulBufC *signed_cose)
{
    struct t_cose_key teep_agent_key_pair;
    enum t_cose_err_t t_cose_res = T_COSE_SUCCESS;
    t_cose_res = make_optee_key_pair(
        T_COSE_ALGORITHM_ES256, &teep_agent_key_pair,
        teep_agent_es256_public_key_X, teep_agent_es256_public_key_Y,
        teep_agent_es256_private_key_R);
    if (T_COSE_SUCCESS != t_cose_res) {
        DMSG("make_optee_key_pair fail: %d", t_cose_res);
        return false;
    }

    struct t_cose_sign1_sign_ctx sign_ctx;

    t_cose_sign1_sign_init(&sign_ctx, 0, T_COSE_ALGORITHM_ES256);
    t_cose_sign1_set_signing_key(&sign_ctx, teep_agent_key_pair,
                                 Q_USEFUL_BUF_FROM_SZ_LITERAL("101"));
    t_cose_res =
        t_cose_sign1_sign(&sign_ctx, *sign_target, *workbuf, signed_cose);
    if (T_COSE_SUCCESS != t_cose_res) {
        DMSG("t_cose_sign1_sign fail: %d", t_cose_res);
        free_optee_key_pair(teep_agent_key_pair);
        return false;
    }
    free_optee_key_pair(teep_agent_key_pair);
    return true;
}

bool teep_agent_verify(UsefulBufC *signed_cose,
                       struct t_cose_key *teep_agent_key_pair,
                       UsefulBufC *returned_payload)
{
    struct t_cose_sign1_verify_ctx verify_ctx;
    t_cose_sign1_verify_init(&verify_ctx, 0);

    t_cose_sign1_set_verification_key(&verify_ctx, *teep_agent_key_pair);
    enum t_cose_err_t t_cose_res =
        t_cose_sign1_verify(&verify_ctx, *signed_cose, returned_payload, NULL);

    if (T_COSE_SUCCESS != t_cose_res) {
        DMSG("t_cose_sign1_verify fail: %d", t_cose_res);
        return false;
    } else {
        DMSG("SUCCESS Verify !!!!! %d", t_cose_res);
    }
    return true;
}

void print_binary(const void *object, uint32_t size, const char *object_name)
{
    size_t hexstr_size = size * sizeof(char) * 2 + 1;
    char *hexstr = TEE_Malloc(hexstr_size, TEE_MALLOC_FILL_ZERO);
    to_hex(hexstr, hexstr_size, object, size);
    DMSG("[%s (%d)] 0x%s ", object_name, size, hexstr);
    TEE_Free(hexstr);
}

bool to_hex(char *dest, size_t dest_len, const uint8_t *values, size_t val_len)
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
