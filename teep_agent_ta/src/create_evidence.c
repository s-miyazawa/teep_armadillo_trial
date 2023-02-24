/*
 * Copyright (c) 2023 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <qcbor/UsefulBuf.h>
#include <qcbor/qcbor_encode.h>
#include <tee_api.h>
#include <teep/teep_message_data.h>

#include "teep_agent_ta.h"
#include "teep_agent/api.h"
#include "teep_agent/utils.h"

/*
  create a new raw evidence

  UsefulBufC in_eat_token
  UsefulBufC in_verifier_nonce

  UsefulBuf out_query_response_cbor_buf
  UsefulBufC *out_constructed_payload
*/
static QCBORError build_evidence(UsefulBufC in_eat_nonce,
                                 UsefulBufC in_verifier_nonce,
                                 UsefulBuf out_evidence_cbor_buffer,
                                 UsefulBufC *out_constructed_payload)
{
    QCBOREncodeContext cbor_encode;

    QCBOREncode_Init(&cbor_encode, out_evidence_cbor_buffer);
    QCBOREncode_OpenMap(&cbor_encode);

    /* / eat_nonce /       10: h'948f8860d13a463e’ */
    QCBOREncode_AddBytesToMapN(&cbor_encode, 10, in_eat_nonce);

    /* / ueid / 256: h'0198f50a4ff6c05861c8860d13a638ea', */
    QCBOREncode_AddBytesToMapN(
        &cbor_encode, 256,
        ((UsefulBufC){ (uint8_t[]){ 0x01, 0x98, 0xf5, 0x0a, 0x4f, 0xf6, 0xc0,
                                    0x58, 0x61, 0xc8, 0x86, 0x0d, 0x13, 0xa6,
                                    0x38, 0xea },
                       16 }));

    /* / oemid /          258: h'894823', / IEEE OUI format OEM ID / */
    QCBOREncode_AddBytesToMapN(
        &cbor_encode, 258,
        ((UsefulBufC){ (uint8_t[]){ 0x89, 0x48, 0x23 }, 3 }));

    /* / hwmodel /        259: h'549dcecc8b987c737b44e40f7c635ce8’ */
    QCBOREncode_AddBytesToMapN(
        &cbor_encode, 259,
        ((UsefulBufC){ (uint8_t[]){ 0x54, 0x9d, 0xce, 0xcc, 0x8b, 0x98, 0x7c,
                                    0x73, 0x7b, 0x44, 0xe4, 0x0f, 0x7c, 0x63,
                                    0x5c, 0xe8 },
                       32 }));
    /* / verifier_nonce / -70000: h'948f8860d13a463e8e’ */
    QCBOREncode_AddBytesToMapN(&cbor_encode, -70000, in_verifier_nonce);
    /* / hwversion /      260: ["1.3.4", 1], / Multipartnumeric  / */
    QCBOREncode_OpenArray(&cbor_encode);
    QCBOREncode_AddText(&cbor_encode, ((UsefulBufC){ "1.3.4", 5 }));
    QCBOREncode_AddInt64(&cbor_encode, 1);
    QCBOREncode_CloseArray(&cbor_encode);

    QCBOREncode_CloseMap(&cbor_encode);
    return QCBOREncode_Finish(&cbor_encode, out_constructed_payload);
}

static void parse_query_request(const teep_query_request_t *query_request)
{
    /* ************************************************************ */
    /* version check */
    /* ************************************************************ */
    if (query_request->contains & TEEP_MESSAGE_CONTAINS_VERSION) {
        for (size_t i = 0; i < query_request->versions.len; i++) {
            DMSG("QUERY_REQUEST:version[%d] = %d", (uint32_t)i,
                 query_request->versions.items[i]);
        }
    }
    /* ************************************************************ */
    /* cipher suit check */
    /* ************************************************************ */
    for (size_t i = 0; i < query_request->supported_cipher_suites.len; i++) {
        DMSG("QUERY_REQUEST:CIPHER_SUIT item[%d] = %d", (uint32_t)i,
             query_request->supported_cipher_suites.items[i]
                 .mechanisms->algorithm_id);
        if (query_request->supported_cipher_suites.items[i]
                .mechanisms->algorithm_id == TEEP_COSE_SIGN_ES256) {
            DMSG("QUERY_REQUEST:CIPHER_SUIT OK ES256");
        }
    }
    /* ************************************************************ */
    /* FRESHNESS_MECHANISM check */
    /* ************************************************************ */
    for (size_t i = 0; i < query_request->supported_freshness_mechanisms.len;
         i++) {
        DMSG("QUERY_REQUEST:Freshness item[%d] = %d", (uint32_t)i,
             query_request->supported_freshness_mechanisms.items[i]);
        /* } */
    }

    if (query_request->data_item_requested & BIT(TEEP_DATA_ITEM_INVALID)) {
        DMSG("QUERIY_REQUEST:Request Items:INVALID");
    } else {
        if (query_request->data_item_requested &
            BIT(TEEP_DATA_ITEM_ATTESTATION)) {
            DMSG("QUERIY_REQUEST:Request Items:ATTESTATION");
        }
        if (query_request->data_item_requested &
            BIT(TEEP_DATA_ITEM_TRUSTED_COMPONENTS)) {
            DMSG("QUERIY_REQUEST:Request Items:TRUSTED_COMPONENTS");
        }
        if (query_request->data_item_requested &
            BIT(TEEP_DATA_ITEM_EXTENTIONS)) {
            DMSG("QUERIY_REQUEST:Request Items:TRUSTED_EXTENTIONS");
        }
    }

    /* } */

    /* ************************************************************ */
    /* CHALLENGE check */
    /* ************************************************************ */
    if (query_request->contains & TEEP_MESSAGE_CONTAINS_CHALLENGE) {
        print_binary(query_request->challenge.ptr, query_request->challenge.len,
                     "QUERY_REQUEST:challenge");
    }

    /* ************************************************************ */
    /* TOKEN check */
    /* ************************************************************ */
    if (query_request->contains & TEEP_MESSAGE_CONTAINS_TOKEN) {
        print_binary(query_request->token.ptr, query_request->token.len,
                     "QUERY_REQUEST:token");
    }
}

/*
  This function is an API for TEEP broker to let TEEP agent produce
  Evidence data.

  parameters[0]: in  : Binary data of Query Request (COSE format)
  parameters[1]: in  : Binary data of Verifier Nonce (raw binary)
  parameters[2]: out : Binary data of Evidence (COSE format)
  parameters[3]: out : Binary data of token for TAM (raw binary extracted from
  Query Request)
*/
TEE_Result create_evidence(TEE_Param parameters[4])
{
    TEE_Result result = TEE_SUCCESS;
    /* parameters[0]: in  : Binary data of Query Request (COSE format) */
    UsefulBufC payload_from_tam;
    payload_from_tam.ptr = parameters[0].memref.buffer;
    payload_from_tam.len = parameters[0].memref.size;
    print_binary(payload_from_tam.ptr, payload_from_tam.len,
                 "Pyaload from TAM");

    /* parameters[1]: in  : Binary data of Verifier Nonce (raw binary) */
    UsefulBufC verifier_nonce;
    verifier_nonce.ptr = parameters[1].memref.buffer;
    verifier_nonce.len = parameters[1].memref.size;
    print_binary(verifier_nonce.ptr, verifier_nonce.len,
                 "VerifierNonce from Verifier");

    /*
      Preparation of keys to verify TAM
    */
    enum t_cose_err_t t_cose_res = T_COSE_SUCCESS;
    struct t_cose_key tam_key_pair;
    t_cose_res = make_optee_key_pair(
        T_COSE_ALGORITHM_ES256, &tam_key_pair, tam_es256_public_key_X,
        tam_es256_public_key_Y, tam_es256_private_key_R);
    if (t_cose_res != T_COSE_SUCCESS) {
        DMSG("make_optee_key_pair fail: %d", t_cose_res);
        result = TEE_ERROR_GENERIC;
        goto out;
    }

    /*
      Verify the message from TAM
     */
    UsefulBufC raw_query_request;
    teep_agent_verify(&payload_from_tam, &tam_key_pair, &raw_query_request);
    print_binary(raw_query_request.ptr, raw_query_request.len,
                 "VERIFIED PAYLOAD");

    /*
      convert the raw query resuest binary data into a libteep message structure
    */
    teep_message_t recv_message;
    teep_set_message_from_bytes(raw_query_request.ptr, raw_query_request.len,
                                &recv_message);
    const teep_query_request_t *query_request =
        (const teep_query_request_t *)&recv_message.query_request;
    if (recv_message.teep_message.type == TEEP_TYPE_QUERY_REQUEST) {
        DMSG("TEEP_TYPE_QUERY_REQUEST!!!!");
        parse_query_request(query_request);
    } else {
        DMSG("XXXXXXXXXXXXX:%d ", recv_message.teep_message.type);
    }

    /*
      build Evidence
    */
    UsefulBufC eat_nonce;
    eat_nonce.ptr = query_request->challenge.ptr;
    eat_nonce.len = query_request->challenge.len;
    UsefulBuf evidence_data_buffer;
    evidence_data_buffer.len = TEEP_AGENT_MAX_HEAP_BUFFER_SIZE;
    evidence_data_buffer.ptr =
        TEE_Malloc(evidence_data_buffer.len, TEE_MALLOC_FILL_ZERO);
    UsefulBufC evidence_data;
    build_evidence(eat_nonce, verifier_nonce, evidence_data_buffer,
                   &evidence_data);

    /*
      sign1 to the Evidence
    */
    UsefulBufC signed_cose;
    UsefulBuf workbuf;
    workbuf.len = TEEP_AGENT_MAX_HEAP_BUFFER_SIZE;
    workbuf.ptr = TEE_Malloc(workbuf.len, TEE_MALLOC_FILL_ZERO);
    teep_agent_sign(&workbuf, &evidence_data, &signed_cose);

    /*
      Copy the Evidence data and the token from TAM to REE

      parameters[2]: out : Binary data of Evidence (COSE format)
      parameters[3]: out : Binary data of token for TAM (raw binary extracted
      from
    */
    parameters[2].memref.size = signed_cose.len;
    TEE_MemMove(parameters[2].memref.buffer, signed_cose.ptr, signed_cose.len);
    parameters[3].memref.size = query_request->token.len;
    TEE_MemMove(parameters[3].memref.buffer, query_request->token.ptr,
                query_request->token.len);

out:
    free_optee_key_pair(tam_key_pair);
    TEE_Free(evidence_data_buffer.ptr);
    TEE_Free(workbuf.ptr);
    return result;
}
