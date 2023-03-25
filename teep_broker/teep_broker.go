// Copyright (c) 2023 SECOM CO., LTD. All Rights reserved.
//
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/s-miyazawa/teep_armadillo_trial/teep_broker/tee"
	"github.com/s-miyazawa/teep_armadillo_trial/teep_broker/teep"
)

func printAsCbor(bin []byte) {
	log.Printf("%X\n", bin)
}

func main() {
	// ----------------------------------------------------------------------
	// 1. request "QueryRequest" to the TAM
	//
	//
	// 1.1. TeepBroker -----------[""]----------> TAM
	//
	// 1.2. TeepBroker <---[{QueryRequestBin}]--- TAM
	//
	// note: [] means html body, {} means cose format.
	//
	// ----------------------------------------------------------------------
	tamUrl := "http://192.168.64.4:8888/api/tam_cose"
	if len(os.Args) > 1 {
		tamUrl = os.Args[1]
	}
	queryRequestBin := teep.GetQueryRequest(tamUrl)
	fmt.Printf("\x1b[31m")
	fmt.Printf("\n[queryRequestBin]\n")
	printAsCbor(queryRequestBin)
	fmt.Printf("\x1b[0m")
	// ----------------------------------------------------------------------
	// 2. request "VerifierNonce" to the Veirifier
	//
	//
	// 2.1. TeepBroker -----------[""]---------> Verifier
	//
	// 2.2. TeepBroker <---[VerifierNonceBin]--- Verifier
	//
	// ----------------------------------------------------------------------
	verifierUrl := "http://192.168.64.4:5000/verify"
	if len(os.Args) > 2 {
		verifierUrl = os.Args[2]
	}
	verifierNonceBin := teep.GetVerifierNonce(verifierUrl)
	fmt.Printf("\x1b[32m")
	fmt.Printf("\n[verifierNonceBin]\n")
	printAsCbor(verifierNonceBin)
	fmt.Printf("\x1b[0m")
	// ----------------------------------------------------------------------
	// 3. create Evidence
	//
	//
	// 3.1. TeepBroker --- {QueryRequestBin}, VerifierNonceBin ---> TeepAgent
	//
	// 3.2. TeepBroker <--------- {Evidence}, TamTokenBin --------- TeepAgent
	//
	// ----------------------------------------------------------------------
	evidenceBin, tamTokenBin := tee.CreateEvidence(queryRequestBin, verifierNonceBin)

	fmt.Printf("\x1b[33m")
	fmt.Printf("\n[evidenceBin]\n")
	printAsCbor(evidenceBin)
	fmt.Printf("\x1b[0m")

	fmt.Printf("\x1b[34m")
	fmt.Print("\n[tamTokenBin]\n")
	printAsCbor(tamTokenBin)
	fmt.Printf("\x1b[0m")

	// 4. request Attestation Result to the Verifier
	//
	// 4.1. TeepBroker ---------- {Evidence} --------> Verifier
	//
	// 4.2. TeepBroker <--- {AttestationResultBin} --- Verifier
	//
	// ----------------------------------------------------------------------
	attestationResultBin := teep.GetAttestationResult(verifierUrl, evidenceBin)
	fmt.Printf("\x1b[35m")
	fmt.Printf("\n[attestationResultBin]\n")
	printAsCbor(attestationResultBin)
	fmt.Printf("\x1b[0m")

	// ----------------------------------------------------------------------
	// 5. create QueryResponse
	//
	// 5.1. TeepBroker --- {AttestationReusltBin}, TamTokenBin ---> TeepAgent
	//
	// 5.2. TeepBroker <------------- {QueryResponse} ------------- TeepAgent
	//
	// ----------------------------------------------------------------------
	var queryResponseBin = tee.CreateQueryResponse(attestationResultBin, tamTokenBin)
	fmt.Printf("\x1b[36m")
	fmt.Print("\n[queryResponseBin]\n")
	printAsCbor(queryResponseBin)
	fmt.Printf("\x1b[0m")

	// ----------------------------------------------------------------------
	// 6. send QueryResponse (inc. AR and token) to the TAM
	//
	// 6.1. TeepBroker --- [{QueryResponseBin}] ---> TAM
	//
	// 6.2. TeepBroker <------- [{Update}]---------- TAM
	// ----------------------------------------------------------------------
	updateBin := teep.SendQueryResponse(tamUrl, queryResponseBin)

	// ----------------------------------------------------------------------
	// 7. receive Update form the TAM
	// ----------------------------------------------------------------------
	fmt.Printf("\x1b[37m")
	fmt.Print("\n[updateBin]\n")
	printAsCbor(updateBin)
	fmt.Printf("\x1b[0m")

	// ----------------------------------------------------------------------
	// 8. send Success to the TAM
	// ----------------------------------------------------------------------
}
