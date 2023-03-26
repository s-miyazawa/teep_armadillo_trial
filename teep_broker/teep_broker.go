// Copyright (c) 2023 SECOM CO., LTD. All Rights reserved.
//
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"bufio"
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

	const GREEN_REVERSE = "\x1b[7m\x1b[32m"
	const ORANGE_REVERSE = "\x1b[7m\x1b[33m"
	const PURPLE_REVERSE = "\x1b[7m\x1b[35m"
	const WHITE_REVERSE = "\x1b[7m\x1b[47m"

	const GREEN_STR = "\x1b[32m"
	const ORANGE_STR = "\x1b[33m"
	const PURPLE_STR = "\x1b[35m"

	const STRING_RESET = "\x1b[9m\x1b[0m"

	const BORDER_STR = WHITE_REVERSE + "\n.............................................................................." + STRING_RESET + "\n"

	// 1.1. TeepBroker -----------[""]----------> TAM
	fmt.Printf(BORDER_STR)
	fmt.Printf("1.1. ")
	fmt.Printf(GREEN_REVERSE)
	fmt.Printf("Teep Broker")
	fmt.Printf(STRING_RESET)
	fmt.Printf(" ------ ")
	fmt.Printf(GREEN_STR)
	fmt.Printf("POST[\"\"]")
	fmt.Printf(STRING_RESET)
	fmt.Printf(" --------> ")

	fmt.Printf(PURPLE_REVERSE)
	fmt.Printf("TAM\n")
	fmt.Printf(STRING_RESET)

	// 1.2. TeepBroker <---[{QueryRequestBin}]--- TAM
	fmt.Printf("1.2. ")
	fmt.Printf(GREEN_REVERSE)
	fmt.Printf("Teep Broker")
	fmt.Printf(STRING_RESET)
	fmt.Printf(" <-- ")
	fmt.Printf(PURPLE_STR)
	fmt.Printf("[{Query Request}]")
	fmt.Printf(STRING_RESET)
	fmt.Printf(" --- ")

	fmt.Printf(PURPLE_REVERSE)
	fmt.Printf("TAM\n")
	fmt.Printf(STRING_RESET)

	// payload
	fmt.Printf(PURPLE_STR)
	fmt.Printf("\n[Query Request (hex)]\n")
	printAsCbor(queryRequestBin)
	fmt.Printf(STRING_RESET)

	reader := bufio.NewReader(os.Stdin)
	reader.ReadString('\n')

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

	// 2.1. TeepBroker -----------[""]---------> Verifier
	fmt.Printf(BORDER_STR)
	fmt.Printf("2.1. ")
	fmt.Printf(GREEN_REVERSE)
	fmt.Printf("Teep Broker")
	fmt.Printf(STRING_RESET)
	fmt.Printf(" ------- ")
	fmt.Printf(GREEN_STR)
	fmt.Printf("GET[\"\"]")
	fmt.Printf(STRING_RESET)
	fmt.Printf(" -------> ")
	fmt.Printf(ORANGE_REVERSE)
	fmt.Printf("Verifier\n")
	fmt.Printf(STRING_RESET)

	fmt.Printf("2.2. ")
	fmt.Printf(GREEN_REVERSE)
	fmt.Printf("Teep Broker")
	fmt.Printf(STRING_RESET)
	fmt.Printf(" <-- ")
	fmt.Printf(ORANGE_STR)
	fmt.Printf("[Verifier Nonce]")
	fmt.Printf(STRING_RESET)
	fmt.Printf(" --- ")

	fmt.Printf(ORANGE_REVERSE)
	fmt.Printf("Verifier\n")
	fmt.Printf(STRING_RESET)

	// payload
	fmt.Printf(ORANGE_STR)
	fmt.Printf("\n[Verifier Nonce (hex)]\n")
	printAsCbor(verifierNonceBin)
	fmt.Printf(STRING_RESET)
	reader.ReadString('\n')
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
	// 3.1. TeepBroker --- {QueryRequestBin}, VerifierNonceBin ---> TeepAgent
	//
	// 3.2. TeepBroker <--------- {Evidence}, TamTokenBin --------- TeepAgent

	fmt.Printf(BORDER_STR)
	fmt.Printf("3.1. ")
	fmt.Printf(GREEN_REVERSE)
	fmt.Printf("Teep Broker")
	fmt.Printf(STRING_RESET)
	fmt.Printf(" ==== ")
	fmt.Printf(PURPLE_STR)
	fmt.Printf("{Query Request}")
	fmt.Printf(STRING_RESET)
	fmt.Printf(", ")
	fmt.Printf(ORANGE_STR)
	fmt.Printf("Verifier Nonce")
	fmt.Printf(STRING_RESET)
	fmt.Printf(" ===> ")
	fmt.Printf(GREEN_REVERSE)
	fmt.Printf("Teep Agent\n")
	fmt.Printf(STRING_RESET)

	fmt.Printf("3.2. ")
	fmt.Printf(GREEN_REVERSE)
	fmt.Printf("Teep Broker")
	fmt.Printf(STRING_RESET)
	fmt.Printf(" <========= ")
	fmt.Printf(GREEN_STR)
	fmt.Printf("{Evidence}")
	fmt.Printf(STRING_RESET)
	fmt.Printf(", ")
	fmt.Printf(PURPLE_STR)
	fmt.Printf("Tam Token")
	fmt.Printf(STRING_RESET)
	fmt.Printf(" ======== ")
	fmt.Printf(GREEN_REVERSE)
	fmt.Printf("Teep Agent\n")
	fmt.Printf(STRING_RESET)

	fmt.Printf(GREEN_STR)
	fmt.Print("\n[Evidence]\n")
	printAsCbor(evidenceBin)
	fmt.Printf(PURPLE_STR)
	fmt.Print("[TAM Token]\n")
	printAsCbor(tamTokenBin)
	fmt.Printf(STRING_RESET)

	reader.ReadString('\n')

	// ----------------------------------------------------------------------
	// 4. request Attestation Result to the Verifier
	//
	// 4.1. TeepBroker ---------- {Evidence} --------> Verifier
	//
	// 4.2. TeepBroker <--- {AttestationResultBin} --- Verifier
	//
	// ----------------------------------------------------------------------

	// 4.1. TeepBroker ---------- {Evidence} --------> Verifier
	fmt.Printf(BORDER_STR)
	attestationResultBin := teep.GetAttestationResult(verifierUrl, evidenceBin)
	fmt.Printf("4.1. ")
	fmt.Printf(GREEN_REVERSE)
	fmt.Printf("Teep Broker")
	fmt.Printf(STRING_RESET)
	fmt.Printf(" ---------- ")
	fmt.Printf(GREEN_STR)
	fmt.Printf("{Evidence}")
	fmt.Printf(STRING_RESET)
	fmt.Printf(" ---------> ")
	fmt.Printf(ORANGE_REVERSE)
	fmt.Printf("Verifier\n")
	fmt.Printf(STRING_RESET)

	// 4.2. TeepBroker <--- {AttestationResultBin} --- Verifier
	fmt.Printf("4.2. ")
	fmt.Printf(GREEN_REVERSE)
	fmt.Printf("Teep Broker")
	fmt.Printf(STRING_RESET)
	fmt.Printf(" <---- ")
	fmt.Printf(ORANGE_STR)
	fmt.Printf("{Attestation Result}")
	fmt.Printf(STRING_RESET)
	fmt.Printf(" ----- ")
	fmt.Printf(ORANGE_REVERSE)
	fmt.Printf("Verifier\n")
	fmt.Printf(STRING_RESET)
	fmt.Printf(ORANGE_STR)
	fmt.Printf("\n[Attestation Result]\n")
	printAsCbor(attestationResultBin)
	fmt.Printf(STRING_RESET)

	reader.ReadString('\n')
	// ----------------------------------------------------------------------
	// 5. create QueryResponse
	//
	// 5.1. TeepBroker --- {AttestationReusltBin}, TamTokenBin ---> TeepAgent
	//
	// 5.2. TeepBroker <------------- {QueryResponse} ------------- TeepAgent
	//
	// ----------------------------------------------------------------------
	var queryResponseBin = tee.CreateQueryResponse(attestationResultBin, tamTokenBin)
	fmt.Printf(BORDER_STR)
	// 5.1. TeepBroker --- {AttestationReusltBin}, TamTokenBin ---> TeepAgent
	fmt.Printf("5.1. ")
	fmt.Printf(GREEN_REVERSE)
	fmt.Printf("Teep Broker")
	fmt.Printf(STRING_RESET)
	fmt.Printf(" ==== ")
	fmt.Printf(ORANGE_STR)
	fmt.Printf("{Attestation Reuslt}")
	fmt.Printf(STRING_RESET)
	fmt.Printf(", ")
	fmt.Printf(PURPLE_STR)
	fmt.Print("[TAM Token]")
	fmt.Printf(STRING_RESET)
	fmt.Printf(" ===> ")
	fmt.Printf(GREEN_REVERSE)
	fmt.Printf("Teep Agent\n")
	fmt.Printf(STRING_RESET)
	// 5.2. TeepBroker <------------- {QueryResponse} ------------- TeepAgent
	fmt.Printf("5.2. ")
	fmt.Printf(GREEN_REVERSE)
	fmt.Printf("Teep Broker")
	fmt.Printf(STRING_RESET)
	fmt.Printf(" <============ ")
	fmt.Printf(GREEN_STR)
	fmt.Printf("{Query Response}")
	fmt.Printf(STRING_RESET)
	fmt.Printf(" ============ ")
	fmt.Printf(GREEN_REVERSE)
	fmt.Printf("Teep Agent\n")
	fmt.Printf(STRING_RESET)

	fmt.Printf(GREEN_STR)
	fmt.Printf("\n[Query Response]\n")
	printAsCbor(queryResponseBin)
	reader.ReadString('\n')
	fmt.Printf(STRING_RESET)
	// ----------------------------------------------------------------------
	// 6. send QueryResponse (inc. AR and token) to the TAM
	//
	// 6.1. TeepBroker --- [{QueryResponseBin}] ---> TAM
	//
	// 6.2. TeepBroker <------- [{Update}]---------- TAM
	// ----------------------------------------------------------------------
	updateBin := teep.SendQueryResponse(tamUrl, queryResponseBin)
	fmt.Printf(STRING_RESET)
	fmt.Printf(BORDER_STR)
	fmt.Printf(STRING_RESET)
	// 6.1. TeepBroker --- [{QueryResponseBin}] ---> TAM
	fmt.Printf("6.1. ")
	fmt.Printf(GREEN_REVERSE)
	fmt.Printf("Teep Broker")
	fmt.Printf(STRING_RESET)
	fmt.Printf(" --- ")
	fmt.Printf(GREEN_STR)
	fmt.Printf("[{Query Response}]")
	fmt.Printf(STRING_RESET)
	fmt.Printf(" ---> ")
	fmt.Printf(PURPLE_REVERSE)
	fmt.Printf("TAM\n")
	fmt.Printf(STRING_RESET)
	// 6.2. TeepBroker <------- [{Update}]---------- TAM
	fmt.Printf("6.2. ")
	fmt.Printf(GREEN_REVERSE)
	fmt.Printf("Teep Broker")
	fmt.Printf(STRING_RESET)
	fmt.Printf(" <------- ")
	fmt.Printf(PURPLE_STR)
	fmt.Printf("[{Update}]")
	fmt.Printf(STRING_RESET)
	fmt.Printf(" ------- ")
	fmt.Printf(PURPLE_REVERSE)
	fmt.Printf("TAM\n")
	fmt.Printf(STRING_RESET)

	// ----------------------------------------------------------------------
	// 7. receive Update form the TAM
	// ----------------------------------------------------------------------
	fmt.Printf(PURPLE_STR)
	fmt.Print("\n[Update]\n")
	printAsCbor(updateBin)
	reader.ReadString('\n')
	fmt.Printf(STRING_RESET)
	// ----------------------------------------------------------------------
	// 8. send Success to the TAM
	// ----------------------------------------------------------------------
}
