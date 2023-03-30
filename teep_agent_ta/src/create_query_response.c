/*
 * Copyright (c) 2023 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "tee_api_defines.h"
#include "teep_agent/utils.h"
#include <qcbor/UsefulBuf.h>
#include <qcbor/qcbor_encode.h>
#include <tee_api.h>
#include <teep/teep_common.h>
#include <teep/teep_message_data.h>

#include "teep_agent_ta.h"
#include "teep_agent/api.h"

/*
Only one type of cipher is supported yet.
[CBOR_TAG_COSE_SIGN1, T_COSE_ALGORITHM_ES256]
*/
#define SUPPORTED_CIPHER_SUITES_LEN 1
static const teep_cipher_suite_t supported_cipher_suites[SUPPORTED_CIPHER_SUITES_LEN] = {
    {
        .mechanisms[0] = {
            .cose_tag = CBOR_TAG_COSE_SIGN1,
            .algorithm_id = T_COSE_ALGORITHM_ES256,
        },
        .mechanisms[1] = {
            0
        }
    }
};

/*
  create a new raw query response

  UsefulBufC in_tam_token
  UsefulBufC in_attestation_payload

  UsefulBuf out_query_response_cbor_buf
  UsefulBufC *out_constructed_payload
*/
static void build_query_response(UsefulBufC in_tam_token,
                                 UsefulBufC in_attestation_payload,
                                 UsefulBuf out_query_response_cbor_buf,
                                 UsefulBufC *out_constructed_payload)
{
    teep_query_response_t query_response;
    //   / type: / 2 / TEEP-TYPE-query-response /
    query_response.type = TEEP_TYPE_QUERY_RESPONSE;

    //   / options: /
    query_response.contains = 0;
    //   {
    //     / token / 20 : h'A0A1A2A3A4A5A6A7A8A9AAABACADAEAF',
    query_response.token.ptr = in_tam_token.ptr;
    query_response.token.len = in_tam_token.len;
    query_response.contains |= TEEP_MESSAGE_CONTAINS_TOKEN;

    //     / selected-cipher-suite / 5 : [ [ 18, -7 ] ] / only use ES256 /,
    query_response.selected_teep_cipher_suite = supported_cipher_suites[0];
    query_response.contains |= TEEP_MESSAGE_CONTAINS_SELECTED_TEEP_CIPHER_SUITE;

    //     / selected-version / 6 : 0,
    query_response.selected_version = TEEP_PROTOCOL_VERSION;
    query_response.contains |= TEEP_MESSAGE_CONTAINS_VERSIONS;

    //     / attestation-payload / 7 : h'' / empty only for example purpose /,
    query_response.attestation_payload.ptr = in_attestation_payload.ptr;
    query_response.attestation_payload.len = in_attestation_payload.len;
    query_response.contains |= TEEP_MESSAGE_CONTAINS_ATTESTATION_PAYLOAD;

    uint8_t manifest[] = {
        0x81, 0x48, 0x74,0x63, 0x32, 0x2E, 0x73, 0x75, 0x69,0x74
    };

    // "suit-enclave-hello.suit"
    UsefulBufC requesting_manifest = (UsefulBufC) {
        .ptr = manifest,
        .len = sizeof(manifest)
    };
    query_response.contains |= TEEP_MESSAGE_CONTAINS_REQUESTED_TC_LIST;
    query_response.requested_tc_list.len = 1;
    query_response.requested_tc_list.items[0] = (teep_requested_tc_info_t) {
        .contains = TEEP_MESSAGE_CONTAINS_TC_MANIFEST_SEQUENCE_NUMBER | TEEP_MESSAGE_CONTAINS_HAVE_BINARY,
        .component_id = (teep_buf_t){.ptr = requesting_manifest.ptr, .len = requesting_manifest.len},
        .tc_manifest_sequence_number = 1,
        .have_binary = false
    };

    //     / tc_list
    query_response.requested_tc_list.len = 1;
    query_response.contains |= TEEP_MESSAGE_CONTAINS_REQUESTED_TC_LIST;
    //   }

    /*
      encode structure into cbor
    */
    teep_err_t result = teep_encode_message((teep_message_t *)&query_response,
                                            &out_query_response_cbor_buf.ptr,
                                            &out_query_response_cbor_buf.len);
    out_constructed_payload->ptr = out_query_response_cbor_buf.ptr;
    out_constructed_payload->len = out_query_response_cbor_buf.len;
    if (TEEP_SUCCESS != result) {
        DMSG("ERROR!");
    }
}

/*
  This function is an API for TEEP broker to let TEEP agent produce
  Query Response data.

  parameters[0]: in  : Binary data of Attestation Result (COSE format)
  parameters[1]: in  : Binary data of token for TAM (raw binary)
  parameters[2]: out : Binary data of Query Response (COSE format)
*/
TEE_Result create_query_response(TEE_Param parameters[4])
{
    /* parameters[0]: in  : Binary data of Attestation Result (COSE format) */
    UsefulBufC attestation_result;
    attestation_result.ptr = parameters[0].memref.buffer;
    attestation_result.len = parameters[0].memref.size;
    print_binary(attestation_result.ptr, attestation_result.len,
                 "Attestation Result");

    /* parameters[1]: in  : Binary data of token for TAM (raw binary) */
    UsefulBufC tam_token;
    tam_token.ptr = parameters[1].memref.buffer;
    tam_token.len = parameters[1].memref.size;
    print_binary(tam_token.ptr, tam_token.len, "TAM Token");

    /*
      build cbor data of a new raw query request
    */
    TEE_Result ret = TEE_SUCCESS;
    UsefulBufC query_response;
    UsefulBuf query_response_buf;
    query_response_buf.len = TEEP_AGENT_MAX_HEAP_BUFFER_SIZE;
    query_response_buf.ptr =
        TEE_Malloc(query_response_buf.len, TEE_MALLOC_FILL_ZERO);
    build_query_response(tam_token, attestation_result, query_response_buf,
                         &query_response);
    print_binary(query_response.ptr, query_response.len, "Raw Query Response");

    /*
      sign the cbor data to create cose data
    */
    UsefulBufC signed_query_response;
    UsefulBuf workbuf;
    workbuf.len = TEEP_AGENT_MAX_HEAP_BUFFER_SIZE;
    workbuf.ptr = TEE_Malloc(workbuf.len, TEE_MALLOC_FILL_ZERO);
    bool res =
        teep_agent_sign(&workbuf, &query_response, &signed_query_response);
    if (res == false) {
        ret = TEE_ERROR_GENERIC;
        goto out;
    }

    print_binary(signed_query_response.ptr, signed_query_response.len,
                 "Signed Query Response");

    /*
      Copy to REE

      parameters[2]: out : Binary data of Query Response (COSE format)
    */
    parameters[2].memref.size = signed_query_response.len;
    TEE_MemMove(parameters[2].memref.buffer, signed_query_response.ptr,
                signed_query_response.len);
out:
    TEE_Free(query_response_buf.ptr);
    TEE_Free(workbuf.ptr);
    return ret;
}
