/*
 * Copyright (c) 2023 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef TA_TEEP_AGENT_API_H
#define TA_TEEP_AGENT_API_H

#include <tee_api.h>
#include <tee_ta_api.h>

#include <t_cose/t_cose_common.h>
#include <t_cose/t_cose_sign1_sign.h>
#include <t_cose/t_cose_sign1_verify.h>
#include <t_cose/q_useful_buf.h>

#include "teep_agent/utils.h"

/*
  Maximum buffer size that can be used by a single stack variable
*/
#define TEEP_AGENT_MAX_HEAP_BUFFER_SIZE 512

/*
  TEEP protocol version can be supported
*/
#define TEEP_PROTOCOL_VERSION 0

/*
  Key Pair of TeepAgent hardcoded in the program
*/
extern const unsigned char teep_agent_es256_private_key_R[32];
extern const unsigned char teep_agent_es256_public_key_X[32];
extern const unsigned char teep_agent_es256_public_key_Y[32];

/*
  Key Pair of TAM hardcoded in the program
*/
extern const unsigned char tam_es256_private_key_R[32];
extern const unsigned char tam_es256_public_key_X[32];
extern const unsigned char tam_es256_public_key_Y[32];

/*
  Deallocate the OPTEE key pair for t_cose from memory.
*/
void free_optee_key_pair(struct t_cose_key key_pair);

/*
  Generate an OPTEE key pair for t_cose from each value of the
  elliptic curve.
*/
enum t_cose_err_t make_optee_key_pair(int32_t cose_algorithm_id,
                                      struct t_cose_key *key_pair,
                                      const unsigned char param_x[],
                                      const unsigned char param_y[],
                                      const unsigned char param_r[]);

/*
  This function is an API for TEEP broker to let TEEP agent produce
  Evidence data.

  parameters[0]: in  : Binary data of Query Request (COSE format)
  parameters[1]: in  : Binary data of Verifier Nonce (raw binary)

  parameters[2]: out : Binary data of Evidence (COSE format)
  parameters[3]: out : Binary data of token for TAM (raw binary extracted from
  Query Request)
*/
TEE_Result create_evidence(TEE_Param parameters[4]);

/*
  This function is an API for TEEP broker to let TEEP agent produce
  Query Response data.

  parameters[0]: in  : Binary data of Attestation Result (COSE format)
  parameters[1]: in  : Binary data of token for TAM (raw binary)

  parameters[2]: out : Binary data of Query Response (COSE format)
*/
TEE_Result create_query_response(TEE_Param parameters[4]);
#endif /* TA_TEEP_AGENT_H */
