/*
 * Copyright (c) 2023 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "teep_agent_ta.h"
#include "teep_agent/api.h"

TEE_Result TA_CreateEntryPoint(void)
{
    DMSG("has been called");

    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
    DMSG("has been called");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
                                    TEE_Param __maybe_unused params[4],
                                    void __maybe_unused **sess_ctx)
{
    (void)&params;
    (void)&sess_ctx;
    DMSG("has been called");
    uint32_t exp_param_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    if (param_types != exp_param_types) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
    (void)&sess_ctx; /* Unused parameter */
    DMSG("has been called");
}

TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
                                      uint32_t cmd_id, uint32_t param_types,
                                      TEE_Param params[4])
{
    (void)&sess_ctx; /* Unused parameter */
    (void)param_types;

    switch (cmd_id) {
    case TA_CREATE_EVIDENCE:
        return create_evidence(params);
    case TA_CREATE_QUERY_RESPONSE:
        return create_query_response(params);
    default:
        return TEE_ERROR_BAD_PARAMETERS;
    }
}
