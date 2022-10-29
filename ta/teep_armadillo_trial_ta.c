/*
 * Copyright (c) 2022 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <tee_ta_api.h>

#include "qcbor/qcbor_decode.h"

#include <teep_armadillo_trial_ta.h>

#include "ta_keys.h"

#define MAX_HASH_OUTPUT_LENGTH 32 /* sha256 */
void test_libqcbor(void);

void test_libqcbor(void)
{
    uint8_t buf[] = {0x17};
    int len = sizeof(buf);
    QCBORDecodeContext context;
    QCBORDecode_Init(&context, (UsefulBufC){buf, len},
                     QCBOR_DECODE_MODE_NORMAL);
    DMSG("QCBORDecode_Init(&context, (UsefulBufC){buf, "
         "len},QCBORDecode_Init(&context, (UsefulBufC){buf, "
         "len},QCBORDecode_Init(&context, (UsefulBufC){buf, len},");
    QCBORDecode_Finish(&context);
}

int dmsg_hex(const uint8_t *array, const size_t size);

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
    DMSG("has been called");

    return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void) { DMSG("has been called"); }

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
                                    TEE_Param __maybe_unused params[4],
                                    void __maybe_unused **sess_ctx)
{
    uint32_t exp_param_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    DMSG("has been called");

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    /* Unused parameters */
    (void)&params;
    (void)&sess_ctx;

    /*
     * The DMSG() macro is non-standard, TEE Internal API doesn't
     * specify any means to logging from a TA.
     */
    IMSG("This is teep_armadillo_trial first TA!\n");

    /* If return value != TEE_SUCCESS the session will not be created. */
    return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
    (void)&sess_ctx; /* Unused parameter */
    IMSG("Goodbye!\n");
}

int dmsg_hex(const uint8_t *array, const size_t size)
{
    if (array == NULL) {
        return 1;
    }
    for (size_t i = 0; i < size; i++) {
        DMSG("0x%02x ", (unsigned char)array[i]);
    }

    return 0;
}

static int calc_digest(uint32_t hash_alg, const void *msg, size_t msg_len,
                       void *hash, size_t *hash_len)
{
    TEE_OperationHandle operation = (TEE_OperationHandle)NULL;
    TEE_Result ret;

    ret = TEE_AllocateOperation(&operation, hash_alg, TEE_MODE_DIGEST, 0);
    if (ret != TEE_SUCCESS) {
        DMSG("Failed allocate digest operation");
        return 1;
    }

    ret =
        TEE_DigestDoFinal(operation, msg, msg_len, hash, (uint32_t *)hash_len);
    TEE_FreeOperation(operation);

    if (ret != TEE_SUCCESS) {
        DMSG("Final failed");
        return 1;
    }

    return 0;
}

static TEE_Result ta_sign_es256(uint32_t param_types, TEE_Param parameters[4])
{
    TEE_Result ret;
    TEE_ObjectHandle key = NULL;
    TEE_OperationHandle op_sign = NULL, op_verify = NULL;
    uint32_t key_size = 256;
    uint32_t op_max_size = 256;
    uint32_t param_count = 4, fn_ret = 1; /* Initialized error return */
    TEE_Attribute params[4] = {0};
    char hash[MAX_HASH_OUTPUT_LENGTH] = {0};
    size_t hash_len = MAX_HASH_OUTPUT_LENGTH;
    char sig[200] = {0};
    uint32_t sig_len = 200;

    (void)param_types;

    char inbuf[512] = {0};
    size_t inbuf_len = parameters[0].memref.size;
    TEE_MemMove(inbuf, parameters[0].memref.buffer, inbuf_len);
    DMSG("Received Data=====");
    dmsg_hex((const uint8_t *)inbuf, inbuf_len);

    // Qx
    params[0].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_X;
    params[0].content.ref.buffer = (uint8_t *)teep_agent_es256_public_key_X;
    params[0].content.ref.length = 32;

    DMSG("Qx======");
    dmsg_hex(params[0].content.ref.buffer, params[0].content.ref.length);

    // Qy
    params[1].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_Y;
    params[1].content.ref.buffer = (uint8_t *)teep_agent_es256_public_key_Y;
    params[1].content.ref.length = 32;

    DMSG("Qy======");
    dmsg_hex(params[1].content.ref.buffer, params[1].content.ref.length);

    // R
    params[2].attributeID = TEE_ATTR_ECC_PRIVATE_VALUE;
    params[2].content.ref.buffer = (uint8_t *)teep_agent_es256_private_key_R;
    params[2].content.ref.length = 32;

    DMSG("R======");
    dmsg_hex(params[2].content.ref.buffer, params[2].content.ref.length);

    // Curve
    params[3].attributeID = TEE_ATTR_ECC_CURVE;
    params[3].content.value.a = TEE_ECC_CURVE_NIST_P256;
    params[3].content.value.b = 0;

    DMSG("INBUF===========================");
    dmsg_hex((const uint8_t *)inbuf, inbuf_len);

    /* */
    if (calc_digest(TEE_ALG_SHA256, "sample", 6, hash, &hash_len))
        goto err;

    DMSG("Hash======%d", (unsigned int)hash_len);
    dmsg_hex((const uint8_t *)hash, hash_len);

    ret = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR, key_size, &key);
    if (ret != TEE_SUCCESS) { //    if (ret == TEE_ERROR_OUT_OF_MEMORY) {
        DMSG("Fail: TEE_AllocateTransientObject : 0x%x", ret);
        goto err;
    }

    ret = TEE_PopulateTransientObject(key, params, param_count);
    if (ret != TEE_SUCCESS) {
        DMSG("Fail: TEE_PopulateTransientObject : 0x%x", ret);
        goto err;
    }

    ret = TEE_AllocateOperation(&op_sign, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN,
                                op_max_size);
    if (ret != TEE_SUCCESS) {
        DMSG("Fail: TEE_AllocateOperation : 0x%x", ret);
        goto err;
    }

    ret = TEE_SetOperationKey(op_sign, key);
    if (ret != TEE_SUCCESS) {
        DMSG("Fail: TEE_SetOperationKey : 0x%x", ret);
        goto err;
    }

    ret = TEE_AllocateOperation(&op_verify, TEE_ALG_ECDSA_P256, TEE_MODE_VERIFY,
                                op_max_size);
    if (ret != TEE_SUCCESS) {
        DMSG("Fail: TEE_AllocateOperation : 0x%x", ret);
        goto err;
    }

    ret = TEE_SetOperationKey(op_verify, key);
    if (ret != TEE_SUCCESS) {
        DMSG("Fail: TEE_SetOperationKey : 0x%x", ret);
        goto err;
    }

    ret = TEE_AsymmetricSignDigest(op_sign, NULL, 0, hash, hash_len, sig,
                                   &sig_len);
    if (ret != TEE_SUCCESS) {
        DMSG("Fail: TEE_AsymmetricSignDigest : 0x%x", ret);
        goto err;
    }
    parameters[1].memref.size = sig_len;
    TEE_MemMove(parameters[1].memref.buffer, sig, sig_len);

    DMSG("Signature ======%d", sig_len);
    dmsg_hex((uint8_t *)sig, sig_len);

    ret = TEE_AsymmetricVerifyDigest(op_verify, NULL, 0, hash, hash_len, sig,
                                     sig_len);
    if (ret != TEE_SUCCESS) {
        DMSG("Fail : TEE_AsymmetricVerifyDigest : 0x%x", ret);
        goto err;
    } else {
        DMSG("Verify Sucsesss!!!!!!!!!!!!!!!!");
    }

    /* *********************************************** */

    ret = TEE_AsymmetricSignDigest(op_sign, NULL, 0, hash, hash_len, sig,
                                   &sig_len);
    if (ret != TEE_SUCCESS) {
        DMSG("Fail: TEE_AsymmetricSignDigest : 0x%x", ret);
        goto err;
    }
    parameters[1].memref.size = sig_len;
    TEE_MemMove(parameters[1].memref.buffer, sig, sig_len);

    DMSG("Signature(2) ======%d", sig_len);
    dmsg_hex((uint8_t *)sig, sig_len);

    ret = TEE_AsymmetricVerifyDigest(op_verify, NULL, 0, hash, hash_len, sig,
                                     sig_len);
    if (ret != TEE_SUCCESS) {
        DMSG("Fail : TEE_AsymmetricVerifyDigest : 0x%x", ret);
        goto err;
    } else {
        DMSG("Verify(2) Sucsesss!!!!!!!!!!!!!!!!");
    }
    /* *********************************************** */

    fn_ret = 0; // OK

err:
    TEE_FreeTransientObject(key);
    TEE_FreeOperation(op_sign);
    TEE_FreeOperation(op_verify);
    return fn_ret;
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
                                      uint32_t cmd_id, uint32_t param_types,
                                      TEE_Param params[4])
{
    (void)&sess_ctx; /* Unused parameter */

    switch (cmd_id) {
        case TA_SIGN_ES256_CMD:
		test_libqcbor();
            return ta_sign_es256(param_types, params);
        default:
            return TEE_ERROR_BAD_PARAMETERS;
    }
}
