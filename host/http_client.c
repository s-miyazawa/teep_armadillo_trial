/*
 * Copyright (c) 2022 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <curl/curl.h>

#include "sign_verify.h"

#include "http_client.h"
#include "teep/teep_cose.h"
#include "teep/teep_message_data.h"
#include "teep/teep_message_print.h"
#include "teep_keys.h"

const char DEFAULT_TAM_URL[] = "http://10.0.2.2:8888/api/tam_cose";
#define MAX_RECEIVE_BUFFER_SIZE 1024
#define MAX_SEND_BUFFER_SIZE 1024
#define MAX_FILE_BUFFER_SIZE 512

#define SUPPORTED_VERSION 0
#define SUPPORTED_CIPHER_SUITES_LEN 1
#define ERR_MSG_BUF_LEN 32
const teep_cipher_suite_t supported_cipher_suites[SUPPORTED_CIPHER_SUITES_LEN] =
    {{.mechanisms = {{.cose_tag = CBOR_TAG_COSE_SIGN1,
                      .algorithm_id = T_COSE_ALGORITHM_ES256},
                     {0}}}};

void useful_buf_strncpy(const char *err_msg, const size_t len, UsefulBuf *dst)
{
    strncpy(dst->ptr, err_msg, len); // '\0' may not be appended at the last
    dst->len = strnlen(dst->ptr, len);
}

teep_err_t create_error(teep_buf_t token, uint64_t err_code,
                        UsefulBuf err_msg_buf, teep_message_t *message)
{
    teep_error_t *error = (teep_error_t *)message;
    error->type = TEEP_TYPE_TEEP_ERROR;
    error->contains = 0;

    if (token.ptr != NULL && 8 <= token.len && token.len <= 64) {
        error->token = token;
        error->contains |= TEEP_MESSAGE_CONTAINS_TOKEN;
    }
    if (err_msg_buf.len > 0) {
        error->err_msg =
            (teep_buf_t){.ptr = err_msg_buf.ptr, .len = err_msg_buf.len};
        error->contains |= TEEP_MESSAGE_CONTAINS_ERR_MSG;
    }

    if (err_code == TEEP_ERR_CODE_PERMANENT_ERROR) {
        if (token.ptr == NULL || token.len < 8 || 64 < token.len) {
            /* the token is incorrect */
            error->err_code = TEEP_ERR_CODE_PERMANENT_ERROR;
        }
    } else if (err_code == TEEP_ERR_CODE_UNSUPPORTED_MSG_VERSION) {
        error->versions.len = 1;
        error->versions.items[0] = SUPPORTED_VERSION;
        error->contains = TEEP_MESSAGE_CONTAINS_VERSION;
        error->err_code = TEEP_ERR_CODE_UNSUPPORTED_MSG_VERSION;
    } else if (err_code == TEEP_ERR_CODE_UNSUPPORTED_CIPHER_SUITES) {
        error->supported_cipher_suites.len = SUPPORTED_CIPHER_SUITES_LEN;
        for (size_t i = 0; i < SUPPORTED_CIPHER_SUITES_LEN; i++) {
            error->supported_cipher_suites.items[i] =
                supported_cipher_suites[i];
        }
        error->contains |= TEEP_MESSAGE_CONTAINS_SUPPORTED_CIPHER_SUITES;
        error->err_code = TEEP_ERR_CODE_UNSUPPORTED_CIPHER_SUITES;
    }
    return TEEP_SUCCESS;
}

teep_err_t create_success_or_error(const teep_update_t *update,
                                   UsefulBuf err_msg_buf,
                                   teep_message_t *message)
{
    if (!(update->contains & TEEP_MESSAGE_CONTAINS_TOKEN) ||
        update->token.len < 8 || 64 < update->token.len) {
        useful_buf_strncpy("INVALID TOKEN", ERR_MSG_BUF_LEN, &err_msg_buf);
        return create_error(update->token, TEEP_ERR_CODE_PERMANENT_ERROR,
                            err_msg_buf, message);
    }

    /* TODO: Process SUIT Manifest
     * MAY cause TEEP_ERR_CODE_TEMPORARY_ERROR, ERR_MANIFEST_PROCESSING_FAILED
     */

    // create SUCCESS message
    teep_success_t *success = (teep_success_t *)message;
    success->type = TEEP_TYPE_TEEP_SUCCESS;
    success->contains = TEEP_MESSAGE_CONTAINS_TOKEN;
    success->token = update->token;
    return TEEP_SUCCESS;
}

teep_err_t
create_query_response_or_error(const teep_query_request_t *query_request,
                               UsefulBuf err_msg_buf, teep_message_t *message)
{
    size_t i;
    uint64_t err_code_contains = 0;
    int32_t version = -1;
    teep_cipher_suite_t cipher_suite = TEEP_CIPHER_SUITE_INVALID;

    if (query_request->contains & TEEP_MESSAGE_CONTAINS_VERSION) {
        for (i = 0; i < query_request->versions.len; i++) {
            if (query_request->versions.items[i] == SUPPORTED_VERSION) {
                /* supported version is found */
                version = SUPPORTED_VERSION;
                break;
            }
        }
    } else {
        /* means version=0 is supported */
        version = 0;
    }
    if (version != SUPPORTED_VERSION) {
        err_code_contains |= TEEP_ERR_CODE_UNSUPPORTED_MSG_VERSION;
        goto error;
    }

    if (!(query_request->contains &
          TEEP_MESSAGE_CONTAINS_SUPPORTED_CIPHER_SUITES)) {
        /* TODO */
        cipher_suite = supported_cipher_suites[0];
    }
    for (i = 0; i < query_request->supported_cipher_suites.len; i++) {
        for (size_t j = 0; j < SUPPORTED_CIPHER_SUITES_LEN; j++) {
            if (teep_cipher_suite_is_same(
                    query_request->supported_cipher_suites.items[i],
                    supported_cipher_suites[j])) {
                /* supported cipher suite is found */
                cipher_suite = supported_cipher_suites[j];
                goto out;
            }
        }
    }
out:

    if (teep_cipher_suite_is_same(cipher_suite, TEEP_CIPHER_SUITE_INVALID)) {
        err_code_contains |= TEEP_ERR_CODE_UNSUPPORTED_CIPHER_SUITES;
        goto error;
    }

    if (query_request->data_item_requested & TEEP_DATA_ITEM_ATTESTATION) {
        // TODO
        err_code_contains |= TEEP_ERR_CODE_PERMANENT_ERROR;
        useful_buf_strncpy("ATTESTATION IS NOT SUPPORTED", ERR_MSG_BUF_LEN,
                           &err_msg_buf);
        goto error;
    }

error: /* would be unneeded if the err-code becomes bit field */
    if (err_code_contains != 0) {
        return create_error(query_request->token, err_code_contains,
                            err_msg_buf, message);
    }

    teep_query_response_t *query_response = (teep_query_response_t *)message;
    memset(query_response, 0, sizeof(teep_query_response_t));
    query_response->type = TEEP_TYPE_QUERY_RESPONSE;
    query_response->contains = TEEP_MESSAGE_CONTAINS_VERSION |
                               TEEP_MESSAGE_CONTAINS_SELECTED_CIPHER_SUITE;
    if (query_request->contains & TEEP_MESSAGE_CONTAINS_TOKEN) {
        query_response->token = query_request->token;
        query_response->contains |= TEEP_MESSAGE_CONTAINS_TOKEN;
    }
    query_response->selected_version = version;
    query_response->selected_cipher_suite = cipher_suite;

    if (query_request->data_item_requested &
        TEEP_DATA_ITEM_TRUSTED_COMPONENTS) {
        query_response->contains |= TEEP_MESSAGE_CONTAINS_TC_LIST;
#ifdef ENCODE_SUIT
        // TODO encode SUIT_Component_Identifier
#else
        query_response->tc_list.len = 0;
#endif
    }

    return TEEP_SUCCESS;
}

teep_err_t get_teep_message(const char *tam_url, UsefulBufC send_buf,
                            const teep_key_t *verifying_key, UsefulBuf recv_buf,
                            teep_message_t *message)
{
    teep_err_t result;

    // Send TEEP/HTTP POST request.
    printf("main : Send TEEP/HTTP POST request.\n");
    teep_print_hex_within_max(send_buf.ptr, send_buf.len, send_buf.len);
    printf("\n");
    result = teep_send_http_post(tam_url, send_buf, &recv_buf);
    if (result != TEEP_SUCCESS) {
        return result;
    }

    // Verify and print QueryRequest cose.
    UsefulBufC payload;
    result = teep_verify_cose_sign1(UsefulBuf_Const(recv_buf), verifying_key,
                                    &payload);
    if (result != TEEP_SUCCESS) {
        printf("main : Failed to verify TEEP message. %s(%d)\n",
               teep_err_to_str(result), result);
        return result;
    }

    return teep_set_message_from_bytes(payload.ptr, payload.len, message);
}

static size_t write_callback(void *recv_buffer_ptr, size_t size, size_t nitems,
                             void *user_ptr)
{
    UsefulBuf *recv_buffer = (UsefulBuf *)user_ptr;
    printf("\nwrite_callback : start\n");
    size_t recv_size = size * nitems;

    if (recv_size > recv_buffer->len) {
        recv_size = recv_buffer->len;
    }
    memcpy(recv_buffer->ptr, recv_buffer_ptr, recv_size);
    recv_buffer->len = recv_size;
    return recv_size;
}

teep_err_t teep_send_http_post(const char *url, UsefulBufC send_buffer,
                               UsefulBuf *recv_buffer)
{
    teep_err_t result = TEEP_SUCCESS;
    CURL *curl = NULL;
    CURLcode curl_result;
    struct curl_slist *curl_slist = NULL;

    // Set parameter.
    printf("HTTP POST %s\n", url);
    curl = curl_easy_init();
    if (curl == NULL) {
        printf("teep_send_post_request : curl_easy_init : Fail.\n");
        return TEEP_ERR_UNEXPECTED_ERROR;
    }
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_slist = curl_slist_append(curl_slist, "Accept: application/teep+cbor");
    curl_slist = curl_slist_append(curl_slist, "User-Agent: Foo/1.0");
    curl_slist =
        curl_slist_append(curl_slist, "Content-Type: application/teep+cbor");
    if (UsefulBuf_IsNULLOrEmptyC(send_buffer)) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
    } else {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, send_buffer.len);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, send_buffer.ptr);
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_slist);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, recv_buffer);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    // Send request.
    curl_result = curl_easy_perform(curl);
    if (curl_result != CURLE_OK) {
        printf("teep_send_post_request : curl_easy_perform : Fail.\n");
        result = TEEP_ERR_ON_HTTP_POST;
        goto out;
    }

    // Get status code.
    int64_t response_code = -1;
    curl_result =
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (curl_result != CURLE_OK || response_code < 0 || response_code != 200) {
        result = TEEP_ERR_ABORT;
        goto out;
    }

out:
    curl_easy_cleanup(curl);
    return result;
}

int http_main(int argc, const char **argv)
{
    teep_err_t result;
    typedef enum teep_agent_status {
        WAITING_QUERY_REQUEST,
        WAITING_UPDATE_OR_QUERY_REQUEST,
    } teep_agent_status_t;
    teep_agent_status_t status = WAITING_QUERY_REQUEST;
    const char *tam_url = DEFAULT_TAM_URL;
    if (argc > 1) {
        tam_url = argv[1];
    }
    UsefulBuf_MAKE_STACK_UB(cbor_recv_buf, MAX_RECEIVE_BUFFER_SIZE);
    UsefulBuf_MAKE_STACK_UB(cbor_send_buf, MAX_SEND_BUFFER_SIZE);
    UsefulBuf_MAKE_STACK_UB(cose_send_buf, MAX_SEND_BUFFER_SIZE);

    teep_key_t signing_key;
    result =
        teep_key_init_es256_key_pair(teep_agent_es256_private_key,
                                     teep_agent_es256_public_key, &signing_key);
    if (result != TEEP_SUCCESS) {
        printf("main : Failed to create t_cose key pair. %s(%d)\n",
               teep_err_to_str(result), result);
        return EXIT_FAILURE;
    }

    teep_key_t verifying_key;
    result =
        teep_key_init_es256_public_key(tam_es256_public_key, &verifying_key);
    if (result != TEEP_SUCCESS) {
        printf("main : Failed to parse t_cose public key. %s(%d)\n",
               teep_err_to_str(result), result);
        return EXIT_FAILURE;
    }
    printf("main : Verifying key = ");
    teep_print_hex(tam_es256_public_key, sizeof(tam_es256_public_key));
    printf("\n");

    teep_message_t send_message;
    teep_message_t recv_message;
    UsefulBuf_MAKE_STACK_UB(err_msg_buf, ERR_MSG_BUF_LEN);
    err_msg_buf.len = 0; /* the user have to aware this buffer length */

    /* the first message is NULL on teep over http */
    cose_send_buf.len = 0;

    while (1) {
        result = get_teep_message(tam_url, UsefulBuf_Const(cose_send_buf),
                                  &verifying_key, cbor_recv_buf, &recv_message);
        if (result != TEEP_SUCCESS) {
            if (result == TEEP_ERR_ABORT) {
                /* just the TAM terminated the connection */
                result = TEEP_SUCCESS;
                printf("main : The TAM terminated the connection.\n");
                break;
            } else if (result == TEEP_ERR_VERIFICATION_FAILED) {
                /* could not authenticate the TAM's message, ignore */
                printf("main : Could not authenticate the TAM's message.\n");
                goto interval;
            }
            printf("main : Failed to parse received message. %s(%d)\n",
                   teep_err_to_str(result), result);
            return EXIT_FAILURE;
        }
        teep_print_message(&recv_message, 2, NULL);

        cose_send_buf.len = MAX_SEND_BUFFER_SIZE;
        switch (recv_message.teep_message.type) {
            case TEEP_TYPE_QUERY_REQUEST:
                result = create_query_response_or_error(
                    (const teep_query_request_t *)&recv_message, err_msg_buf,
                    &send_message);
                break;
            case TEEP_TYPE_UPDATE:
                if (status == WAITING_QUERY_REQUEST) {
                    printf("main : Received Update message without "
                           "QueryRequest.\n");
                    goto interval;
                }
                result = create_success_or_error(
                    (const teep_update_t *)&recv_message, err_msg_buf,
                    &send_message);
                break;
            case TEEP_TYPE_TEEP_ERROR:
                printf("main : TAM sent Error.\n");
                break;
            default:
                printf("main : Unexpected message type %d\n.",
                       recv_message.teep_message.type);
                return EXIT_FAILURE;
        }
        if (result != TEEP_SUCCESS) {
            printf("main : Failed to create teep message. %s(%d)\n",
                   teep_err_to_str(result), result);
            return EXIT_FAILURE;
        }

        printf("main : Sending...\n");
        teep_print_message(&send_message, 2, NULL);
        if (status == WAITING_QUERY_REQUEST &&
            send_message.teep_message.type == TEEP_TYPE_QUERY_RESPONSE) {
            status = WAITING_UPDATE_OR_QUERY_REQUEST;
        } else if (status == WAITING_UPDATE_OR_QUERY_REQUEST &&
                   send_message.teep_message.type == TEEP_TYPE_TEEP_SUCCESS) {
            status = WAITING_QUERY_REQUEST;
        }

        cbor_send_buf.len = MAX_SEND_BUFFER_SIZE;
        result = teep_encode_message(&send_message, &cbor_send_buf.ptr,
                                     &cbor_send_buf.len);
        if (result != TEEP_SUCCESS) {
            printf("main : Failed to encode query_response message. %s(%d)\n",
                   teep_err_to_str(result), result);
            return EXIT_FAILURE;
        }
        cose_send_buf.len = MAX_SEND_BUFFER_SIZE;
        result = teep_sign_cose_sign1(UsefulBuf_Const(cbor_send_buf),
                                      &signing_key, &cose_send_buf);
        if (result != TEEP_SUCCESS) {
            printf("main : Failed to sign to query_response message. %s(%d)\n",
                   teep_err_to_str(result), result);
            return EXIT_FAILURE;
        }
    interval:
        sleep(1);
    }

    teep_free_key(&verifying_key);
    teep_free_key(&signing_key);

    return EXIT_SUCCESS;
}
