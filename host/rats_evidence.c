#include "rats_evidence.h"
#include "qcbor/qcbor_encode.h"
#include <stdio.h>
#include <time.h>

// ifdef these out to not have compiler warnings
static void printencoded(const uint8_t *pEncoded, size_t nLen)
{
    size_t i;
    for (i = 0; i < nLen; i++) {
        uint8_t Z = pEncoded[i];
        printf("%02x ", Z);
    }
    printf("\n");

    fflush(stdout);
}

UsefulBufC EncodeRATS_Evidence(const RATS_Evidence *pRATS_Evidence,
                               UsefulBuf Buffer)
{
    /* Set up the encoding context with the output buffer */
    QCBOREncodeContext EncodeCtx;
    QCBOREncode_Init(&EncodeCtx, Buffer);

    /* Proceed to output all the items, letting the internal error
     * tracking do its work */
    QCBOREncode_OpenMap(&EncodeCtx);
    QCBOREncode_AddBytesToMapN(&EncodeCtx, 1, pRATS_Evidence->Issuer);
    QCBOREncode_AddInt64ToMapN(&EncodeCtx, 6, pRATS_Evidence->Timestamp);
    QCBOREncode_AddBytesToMapN(&EncodeCtx, 10, pRATS_Evidence->Nonce);
    QCBOREncode_CloseMap(&EncodeCtx);

    /* Get the pointer and length of the encoded output. If there was
     * any encoding error, it will be returned here */
    UsefulBufC EncodedCBOR;
    QCBORError uErr;
    uErr = QCBOREncode_Finish(&EncodeCtx, &EncodedCBOR);

    if (uErr != QCBOR_SUCCESS) {
        printf("create_evidence: ERROR!!!!!!!\n");
        return NULLUsefulBufC;
    } else {
        return EncodedCBOR;
    }
}

void RATS_EvidenceInit(RATS_Evidence *evidence)
{
    evidence->Issuer.ptr = "SECOM";
    evidence->Issuer.len = 5;
    evidence->Nonce.ptr = "hogehoge";
    evidence->Nonce.len = 8;
    evidence->Timestamp = (uint64_t)time(NULL);
}

void RunRATS_EvidenceExample(void)
{
    UsefulBuf_MAKE_STACK_UB(RATS_EvidenceBuffer, 300);
    RATS_Evidence Evidence;
    UsefulBufC EncodedRATS_Evidence;
    RATS_EvidenceInit(&Evidence);
    EncodedRATS_Evidence = EncodeRATS_Evidence(&Evidence, RATS_EvidenceBuffer);
    printencoded(EncodedRATS_Evidence.ptr, EncodedRATS_Evidence.len);
}
