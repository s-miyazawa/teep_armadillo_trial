/*
 * Copyright (c) 2023 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef TA_TEEP_AGENT_UTILS_H
#define TA_TEEP_AGENT_UTILS_H
#include <stdlib.h>
#include <qcbor/UsefulBuf.h>
#include <t_cose/t_cose_common.h>

bool teep_agent_hash(uint32_t hash_algo, UsefulBuf* in_target, UsefulBuf* out_sha256);

bool teep_agent_sign(UsefulBuf *workbuf, UsefulBufC *sign_target, UsefulBufC *signed_cose);

bool teep_agent_verify(UsefulBufC *signed_cose,
                       struct t_cose_key *teep_agent_key_pair,
                       UsefulBufC *returned_payload);
void print_binary(const void* object, uint32_t size, const char *object_name);
bool to_hex(char *dest, size_t dest_len, const uint8_t *values, size_t val_len);
#endif /* TA_TEEP_AGENT_UTILS_H */
