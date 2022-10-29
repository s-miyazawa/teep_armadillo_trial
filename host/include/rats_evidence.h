#ifndef RATS_EVIDENCE_H
#define RATS_EVIDENCE_H

/* D.2.  Entity Attestation Token */

/*    This is shown below in CBOR diagnostic form.  Only the payload signed */
/*    by COSE is shown. */

/* D.2.1.  CBOR Diagnostic Notation */

/* / eat-claim-set = / */
/* { */
/*     / issuer /                   1: "joe", */
/*     / timestamp (iat) /          6: 1(1526542894) */
/*     / nonce /                   10: h'948f8860d13a463e8e', */
/*     / secure-boot /             15: true, */
/*     / debug-status /            16: 3, / disabled-permanently / */
/*     / security-level /          14: 3, / secure-restricted / */
/*     / device-identifier /    <TBD>: h'e99600dd921649798b013e9752dcf0c5', */
/*     / vendor-identifier /    <TBD>: h'2b03879b33434a7ca682b8af84c19fd4', */
/*     / class-identifier /     <TBD>: h'9714a5796bd245a3a4ab4f977cb8487f', */
/*     / chip-version /            26: [ "MyTEE", 1 ], */
/*     / component-identifier / <TBD>: h'60822887d35e43d5b603d18bcaa3f08d', */
/*     / version /              <TBD>: "v0.1" */
/* } */

#include "qcbor/qcbor_encode.h"

typedef struct {
    UsefulBufC Issuer;
    int64_t Timestamp;
    UsefulBufC Nonce;
} RATS_Evidence;

UsefulBufC EncodeRATS_Evidence(const RATS_Evidence *pEvidence,
                               UsefulBuf Buffer);
void RunRATS_EvidenceExample(void);
void RATS_EvidenceInit(RATS_Evidence *evidence);

#endif /* RATS_EVIDENCE_H */
