/*
 * Copyright (c) 2023 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef TA_TEEP_AGENT_H
#define TA_TEEP_AGENT_H

/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */

#define TA_TEEP_AGENT_UUID \
    { \
        0xe55897fb, 0x0aad, 0x43ae, \
        { \
            0x83, 0xa9, 0x33, 0x02, 0x24, 0xac, 0xbd, 0x1d \
        } \
    }

/* The function IDs implemented in this TA */
#define TA_CREATE_EVIDENCE       1
#define TA_CREATE_QUERY_RESPONSE 2

#endif /* TA_TEEP_AGENT_H */
