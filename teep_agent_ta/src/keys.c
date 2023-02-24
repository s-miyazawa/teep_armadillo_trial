/*
 * Copyright (c) 2023 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "teep_agent/api.h"

const unsigned char teep_agent_es256_private_key_R[] = {
    0x60, 0xfe, 0x6d, 0xd6, 0xd8, 0x5d, 0x57, 0x40, //
    0xa5, 0x34, 0x9b, 0x6f, 0x91, 0x26, 0x7e, 0xea, //
    0xc5, 0xba, 0x81, 0xb8, 0xcb, 0x53, 0xee, 0x24, //
    0x9e, 0x4b, 0x4e, 0xb1, 0x02, 0xc4, 0x76, 0xb3  //
};

const unsigned char teep_agent_es256_public_key_X[] = {
    0x58, 0x86, 0xcd, 0x61, 0xdd, 0x87, 0x58, 0x62, //
    0xe5, 0xaa, 0xa8, 0x20, 0xe7, 0xa1, 0x52, 0x74, //
    0xc9, 0x68, 0xa9, 0xbc, 0x96, 0x04, 0x8d, 0xdc, //
    0xac, 0xe3, 0x2f, 0x50, 0xc3, 0x65, 0x1b, 0xa3  //
};

const unsigned char teep_agent_es256_public_key_Y[] = {
    0x9e, 0xed, 0x81, 0x25, 0xe9, 0x32, 0xcd, 0x60, //
    0xc0, 0xea, 0xd3, 0x65, 0x0d, 0x0a, 0x48, 0x5c, //
    0xf7, 0x26, 0xd3, 0x78, 0xd1, 0xb0, 0x16, 0xed, //
    0x42, 0x98, 0xb2, 0x96, 0x1e, 0x25, 0x8f, 0x1b
};

const unsigned char tam_es256_private_key_R[] = {
    0x84, 0x1a, 0xeb, 0xb7, 0xb9, 0xea, 0x6f, 0x02, //
    0x60, 0xbe, 0x73, 0x55, 0xa2, 0x45, 0x88, 0xb9, //
    0x77, 0xd2, 0x3d, 0x2a, 0xc5, 0xbf, 0x2b, 0x6b, //
    0x2d, 0x83, 0x79, 0x43, 0x2a, 0x1f, 0xea, 0x98  //
};

const unsigned char tam_es256_public_key_X[] = {
    0x0e, 0x90, 0x8a, 0xa8, 0xf0, 0x66, 0xdb, 0x1f, //
    0x08, 0x4e, 0x0c, 0x36, 0x52, 0xc6, 0x39, 0x52, //
    0xbd, 0x99, 0xf2, 0xa5, 0xbd, 0xb2, 0x2f, 0x9e, //
    0x01, 0x36, 0x7a, 0xad, 0x03, 0xab, 0xa6, 0x8b  //
};

const unsigned char tam_es256_public_key_Y[] = {
    0x77, 0xda, 0x1b, 0xd8, 0xac, 0x4f, 0x0c, 0xb4, //
    0x90, 0xba, 0x21, 0x06, 0x48, 0xbf, 0x79, 0xab, //
    0x16, 0x4d, 0x49, 0xad, 0x35, 0x51, 0xd7, 0x1d, //
    0x31, 0x4b, 0x27, 0x49, 0xee, 0x42, 0xd2, 0x9a  //
};

void free_optee_key_pair(struct t_cose_key key_pair)
{
    TEE_FreeTransientObject(key_pair.k.key_ptr);
}

static void create_test_key(TEE_Attribute params[], const unsigned char X[],
                            const unsigned char Y[], const unsigned char R[])
{
    // Qx
    params[0].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_X;
    params[0].content.ref.buffer = (uint8_t *)X;
    params[0].content.ref.length = 32;

    // Qy
    params[1].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_Y;
    params[1].content.ref.buffer = (uint8_t *)Y;
    params[1].content.ref.length = 32;

    // R
    params[2].attributeID = TEE_ATTR_ECC_PRIVATE_VALUE;
    params[2].content.ref.buffer = (uint8_t *)R;
    params[2].content.ref.length = 32;

    // Curve
    params[3].attributeID = TEE_ATTR_ECC_CURVE;
    params[3].content.value.a = TEE_ECC_CURVE_NIST_P256;
    params[3].content.value.b = 0;
}

/**
 * \brief Make a key pair in optee TEE library form.
 *
 * \param[in] cose_algorithm_id  The algorithm to sign with, for example
 *                               \ref T_COSE_ALGORITHM_ES256.
 * \param[out] key_pair          The key pair. This must be freed.
 *
 * The key made here is fixed and just useful for testing.
 */
enum t_cose_err_t make_optee_key_pair(int32_t cose_algorithm_id,
                                      struct t_cose_key *key_pair,
                                      const unsigned char param_x[],
                                      const unsigned char param_y[],
                                      const unsigned char param_r[])
{
    uint32_t optee_key_type = 0;
    uint32_t key_size = 0;
    enum t_cose_err_t return_value = T_COSE_SUCCESS;

    switch (cose_algorithm_id) {
    case T_COSE_ALGORITHM_ES256:
        optee_key_type = TEE_TYPE_ECDSA_KEYPAIR;
        key_size = 256;
        break;
    default:
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    // Key Init
    TEE_ObjectHandle optee_key = NULL;
    TEE_Result ret =
        TEE_AllocateTransientObject(optee_key_type, key_size, &optee_key);
    if (ret != TEE_SUCCESS) {
        DMSG("Fail: TEE_AllocateTransientObject : 0x%x", ret);
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto err;
    }

    TEE_Attribute params[4];
    const uint32_t param_count = 4;
    create_test_key(params, param_x, param_y, param_r);

    ret = TEE_PopulateTransientObject(optee_key, params, param_count);
    if (ret != TEE_SUCCESS) {
        DMSG("Fail: TEE_PopulateTransientObject : 0x%x", ret);
        return_value = T_COSE_ERR_FAIL;
        goto err;
    }

    key_pair->k.key_ptr = optee_key;
    key_pair->crypto_lib = T_COSE_CRYPTO_LIB_OPTEE;
    return_value = T_COSE_SUCCESS;
err:
    return return_value;
}
