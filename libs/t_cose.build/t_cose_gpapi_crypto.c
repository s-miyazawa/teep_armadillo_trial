/*
 * Copyright (c) 2023 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <t_cose_crypto.h>
#include <tee_api.h>

static uint32_t cose_hash_alg_id_to_gpapi(int32_t cose_hash_alg_id)
{
    if (cose_hash_alg_id == COSE_ALGORITHM_SHA_256) {
        return TEE_ALG_SHA256;
    } else {
        return UINT32_MAX;
    }
}

/*
 * See documentation in t_cose_crypto.h
 *
 * This will typically not be referenced and thus not linked,
 * for deployed code. This is mainly used for test.
 */
bool t_cose_crypto_is_algorithm_supported(int32_t cose_algorithm_id)
{
    return cose_algorithm_id == COSE_ALGORITHM_ES256;
}

/*
 * Public Interface. See documentation in t_cose_crypto.h
 *
 * \brief Returns the size of a signature given the key and algorithm.
 *
 * \param[in] cose_algorithm_id  The algorithm ID
 * \param[in] signing_key        Key to compute size of
 * \param[out] sig_size          The returned size in bytes.
 *
 * \return An error code or \ref T_COSE_SUCCESS.
 *
 * This is used the caller wishes to compute the size of a token in
 * order to allocate memory for it.
 *
 * The size of a signature depends primarily on the key size but it is
 * usually necessary to know the algorithm too.
 *
 * This always returns the exact size of the signature.
 */
enum t_cose_err_t t_cose_crypto_sig_size(int32_t cose_algorithm_id,
                                         struct t_cose_key signing_key,
                                         size_t *sig_size)
{
    (void)signing_key;
    if (cose_algorithm_id != COSE_ALGORITHM_ES256) {
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }
    *sig_size = 64;
    return T_COSE_SUCCESS;
}

/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t t_cose_crypto_sign(const int32_t cose_algorithm_id,
                                     const struct t_cose_key signing_key,
                                     const struct q_useful_buf_c hash_to_sign,
                                     const struct q_useful_buf signature_buffer,
                                     struct q_useful_buf_c *signature)
{
    if (!t_cose_crypto_is_algorithm_supported(cose_algorithm_id)) {
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }
    TEE_Result ret = TEE_SUCCESS;
    TEE_OperationHandle op_sign = NULL;
    uint32_t op_max_size = 256;
    ret = TEE_AllocateOperation(&op_sign, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN,
                                op_max_size);
    if (ret != TEE_SUCCESS) {
        DMSG("Fail: TEE_SetOperationKey : 0x%x", ret);
        return T_COSE_ERR_FAIL;
    }

    ret = TEE_SetOperationKey(op_sign, signing_key.k.key_ptr);
    if (ret != TEE_SUCCESS) {
        DMSG("Fail: TEE_SetOperationKey : 0x%x", ret);
        return T_COSE_ERR_FAIL;
    }

    uint32_t sig_len = signature_buffer.len;
    ret = TEE_AsymmetricSignDigest(op_sign, NULL, 0, hash_to_sign.ptr,
                                   hash_to_sign.len, signature_buffer.ptr,
                                   &sig_len);
    if (ret == TEE_SUCCESS) {
        signature->ptr = signature_buffer.ptr;
        signature->len = sig_len;

        /* char hexstr[1024]; */
        /* to_hex(hexstr, 1024, signature->ptr, signature->len); */
        /* DMSG("signature->ptr = %s", hexstr); */
        /* DMSG("sig_len = %d", sig_len); */
        /* TEE_FreeTransientObject(signing_key.k.key_ptr); */
        TEE_FreeOperation(op_sign);
        return T_COSE_SUCCESS;
    } else {
        DMSG("Fail: TEE_AsymmetricSignDigest : 0x%x", ret);
        signature->ptr = NULL;
        signature->len = 0;
        /* TEE_FreeTransientObject(signing_key.k.key_ptr); */
        TEE_FreeOperation(op_sign);
        return T_COSE_ERR_SIG_FAIL;
    }
}

enum t_cose_err_t t_cose_crypto_verify(int32_t cose_algorithm_id,
                                       struct t_cose_key verification_key,
                                       struct q_useful_buf_c kid,
                                       struct q_useful_buf_c hash_to_verify,
                                       struct q_useful_buf_c signature)
{
    (void)kid;
    if (!t_cose_crypto_is_algorithm_supported(cose_algorithm_id)) {
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }
    TEE_OperationHandle op_verify = NULL;
    uint32_t op_max_size = 256;
    TEE_Result ret = TEE_AllocateOperation(&op_verify, TEE_ALG_ECDSA_P256,
                                           TEE_MODE_VERIFY, op_max_size);
    if (ret != TEE_SUCCESS) {
        DMSG("Fail: TEE_AllocateOperation : 0x%x", ret);
        goto err;
    }

    ret = TEE_SetOperationKey(op_verify, verification_key.k.key_ptr);
    if (ret != TEE_SUCCESS) {
        DMSG("Fail: TEE_SetOperationKey : 0x%x", ret);
        goto err;
    }

    ret = TEE_AsymmetricVerifyDigest(op_verify, NULL, 0, hash_to_verify.ptr,
                                     hash_to_verify.len, signature.ptr,
                                     signature.len);

    if (ret != TEE_SUCCESS) {
        DMSG("Fail: TEE_AsymmetricVerifyDigest : 0x%x", ret);
        goto err;
    }
    DMSG("VERIFY: SUCESS!!!!!!!!!");
    TEE_FreeOperation(op_verify);
    return T_COSE_SUCCESS;
err:
    TEE_FreeOperation(op_verify);
    return T_COSE_ERR_SIG_VERIFY;
}

/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t t_cose_crypto_hash_start(struct t_cose_crypto_hash *hash_ctx,
                                           int32_t cose_hash_alg_id)
{
    uint32_t algorithm = cose_hash_alg_id_to_gpapi(cose_hash_alg_id);
    hash_ctx->status =
        TEE_AllocateOperation(&hash_ctx->ctx, algorithm, TEE_MODE_DIGEST, 0);
    if (hash_ctx->status == TEE_SUCCESS) {
        return T_COSE_SUCCESS;
    } else {
        DMSG("Fail: TEE_AllocateOperation : 0x%x", hash_ctx->status);
        return T_COSE_ERR_HASH_GENERAL_FAIL;
    }
}

/*
 * See documentation in t_cose_crypto.h
 */
void t_cose_crypto_hash_update(struct t_cose_crypto_hash *hash_ctx,
                               struct q_useful_buf_c data_to_hash)
{
    if (hash_ctx->status != TEE_SUCCESS) {
        DMSG("Fail: check hash_ctx->status: 0x%x", hash_ctx->status);
        return;
    }

    if (data_to_hash.ptr == NULL) {
        return;
    }
    TEE_DigestUpdate(hash_ctx->ctx, data_to_hash.ptr,
                     (uint32_t)data_to_hash.len);
}

/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_hash_finish(struct t_cose_crypto_hash *hash_ctx,
                          struct q_useful_buf buffer_to_hold_result,
                          struct q_useful_buf_c *hash_result)
{
    if (hash_ctx->status != TEE_SUCCESS) {
        DMSG("Fail: 0x%x", hash_ctx->status);
        return T_COSE_ERR_HASH_GENERAL_FAIL;
    }
    uint32_t len = buffer_to_hold_result.len;
    hash_ctx->status = TEE_DigestDoFinal(hash_ctx->ctx, NULL, 0,
                                         buffer_to_hold_result.ptr, &len);
    buffer_to_hold_result.len = len;
    if (hash_ctx->status != TEE_SUCCESS) {
        DMSG("Fail: TEE_DigestDoFinal: 0x%x", hash_ctx->status);
        return T_COSE_ERR_HASH_GENERAL_FAIL;
    }
    hash_result->ptr = buffer_to_hold_result.ptr;
    hash_result->len = buffer_to_hold_result.len;
    return T_COSE_SUCCESS;
}
