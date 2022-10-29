#include "http_client_simple_verifier.h"
#include "rats_evidence.h"
#include "teep/teep_cose.h"
#include "teep/teep_message_data.h"
#include "teep/teep_message_print.h"
#include <curl/curl.h>
#include <stdio.h>

#include "teep_agent_es256_private_key.h"
#include "teep_agent_es256_public_key.h"
const unsigned char *teep_private_key = org_teep_agent_es256_private_key;
const unsigned char *teep_public_key = org_teep_agent_es256_public_key;

void simple_verifier_client(void)
{
    UsefulBuf_MAKE_STACK_UB(RATS_EvidenceBuffer, 300);
    RATS_Evidence Evidence;
    UsefulBufC EncodedRATS_Evidence;
    RATS_EvidenceInit(&Evidence);
    EncodedRATS_Evidence = EncodeRATS_Evidence(&Evidence, RATS_EvidenceBuffer);
    teep_key_t key_pair;
    int32_t result;
    result = teep_key_init_es256_key_pair(teep_private_key, teep_public_key,
                                          &key_pair);

    UsefulBuf_MAKE_STACK_UB(signed_cose, 512);
    result =
        teep_sign_cose_sign1(EncodedRATS_Evidence, &key_pair, &signed_cose);

    teep_print_hex_within_max(signed_cose.ptr, signed_cose.len,
                              signed_cose.len);
    printf("\n");

    CURL *curl;
    CURLcode res;
    char *DEFAULT_SIMPLE_VERIFIER_URL = "http://10.0.2.2:8080/verify";

    RunRATS_EvidenceExample();

    /* get a curl handle */
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, DEFAULT_SIMPLE_VERIFIER_URL);

        /* Now specify the POST data */
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, signed_cose.len);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, signed_cose.ptr);

        /* Perform the request, res will get the return code */
        res = curl_easy_perform(curl);
        /* Check for errors */
        if (res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));

        /* always cleanup */
        curl_easy_cleanup(curl);
    }
}
