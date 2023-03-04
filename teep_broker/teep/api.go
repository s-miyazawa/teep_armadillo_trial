// Copyright (c) 2023 SECOM CO., LTD. All Rights reserved.
//
// SPDX-License-Identifier: BSD-2-Clause

package teep

import (
	"bytes"
	"io"
	"log"
	"net/http"
)

func sendTeepMessage(method string, url string, payload []byte) []byte {
	client := &http.Client{}

	req, err := http.NewRequest(method, url, bytes.NewReader(payload))
	if err != nil {
		log.Fatal(err.Error())
	}

	req.Header.Set("Accept", "application/teep+cbor")
	req.Header.Add("User-Agent", "Foo/1.0")
	req.Header.Add("Content-Type", "application/teep+cbor")

	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err.Error())
	}
	defer res.Body.Close()

	resultBin, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err.Error())
	}
	return resultBin
}

func GetQueryRequest(url string) []byte {
	return sendTeepMessage("POST", url, []byte(""))
}

func GetVerifierNonce(url string) []byte {
	return sendTeepMessage("GET", url, []byte(""))
}

func GetAttestationResult(url string, evidence []byte) []byte {
	return sendTeepMessage("POST", url, evidence)
}

func SendQueryResponse(url string, queryResponse []byte) []byte {
	return sendTeepMessage("POST", url, queryResponse)
}
