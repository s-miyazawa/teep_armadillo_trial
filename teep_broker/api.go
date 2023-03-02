// Copyright (c) 2023 SECOM CO., LTD. All Rights reserved.
//
// SPDX-License-Identifier: BSD-2-Clause

package main

// #include "tee_interface.h"
// #include "stdlib.h"
import "C"

import (
	"bytes"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"unsafe"

	"github.com/fxamacker/cbor"
)

const TA_CREATE_EVIDENCE = 1
const TA_CREATE_QUERY_RESPONSE = 2
const BUFF_SIZE = 1024

func getVerifierNonce(url string) []byte {
	client := &http.Client{}
	body := []byte("")
	req, err := http.NewRequest("GET", url, bytes.NewReader(body))
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
	//ReadAllでResponse Bodyを読み切る
	verifierNonceBin, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err.Error())
	}

	return verifierNonceBin
}

func getAttestationResult(url string, evidenceBin []byte) []byte {
	client := &http.Client{}

	req, err := http.NewRequest("POST", url, bytes.NewReader(evidenceBin))
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
	//ReadAllでResponse Bodyを読み切る
	attestationResultBin, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err.Error())
	}
	return attestationResultBin

}

func sendQueryResponse(url string, queryResponseBin []byte) []byte {
	client := &http.Client{}

	req, err := http.NewRequest("POST", url, bytes.NewReader(queryResponseBin))
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
	//ReadAllでResponse Bodyを読み切る
	updateBin, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err.Error())
	}
	return updateBin
}

func getQueryRequest(url string) []byte {
	client := &http.Client{}

	body := []byte("")

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
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
	//ReadAllでResponse Bodyを読み切る
	queryRequestBin, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err.Error())
	}
	return queryRequestBin
}

func printAsCbor(bin []byte) {
	log.Printf("bin: %x\n", bin)

	var val interface{}
	if err := cbor.Unmarshal(bin, &val); err != nil {
	} else {
		log.Printf("cbor: %x\n", val)
	}
}

func hexstr2bin(str string) []byte {
	buf := bytes.NewBufferString(str)
	dec := hex.NewDecoder(buf)
	bin := make([]byte, hex.DecodedLen(buf.Len()))
	if _, err := dec.Read(bin); err != nil {
		log.Fatalf("ERROR")
	}
	return bin
}

func createEvidence(qReq []byte, vNonce []byte) ([]byte, []byte) {
	qReqBin := C.CBytes(qReq)
	defer C.free(unsafe.Pointer(qReqBin))
	vNonceBin := C.CBytes(vNonce)
	defer C.free(unsafe.Pointer(vNonceBin))

	var out_qReq_bin [BUFF_SIZE]C.char
	var out_qReq_len C.size_t
	var out_vNonce_bin [BUFF_SIZE]C.char
	var out_vNonce_len C.size_t

	rc := C.invoke_teep_agent(
		(*C.char)(qReqBin),
		C.size_t(len(qReq)),
		(*C.char)(vNonceBin),
		C.size_t(len(vNonce)),
		&out_qReq_bin[0],
		&out_qReq_len,
		&out_vNonce_bin[0],
		&out_vNonce_len,
		TA_CREATE_EVIDENCE)

	if rc != 0 {
		log.Fatalf("ERROR")
	}

	evidenceBin := C.GoBytes(unsafe.Pointer(&out_qReq_bin), C.int(out_qReq_len))
	verNonceBin := C.GoBytes(unsafe.Pointer(&out_vNonce_bin), C.int(out_vNonce_len))

	return evidenceBin, verNonceBin
}

func createQueryResponse(attRes []byte, tamToken []byte) []byte {
	attResBin := C.CBytes(attRes)
	defer C.free(unsafe.Pointer(attResBin))
	tamTokenBin := C.CBytes(tamToken)
	defer C.free(unsafe.Pointer(tamTokenBin))

	var out_qResBin [BUFF_SIZE]C.char
	var out_qResBinLen C.size_t
	var out_emptyBin [BUFF_SIZE]C.char
	var out_emptyBinLen C.size_t

	rc := C.invoke_teep_agent(
		(*C.char)(attResBin),
		C.size_t(len(attRes)),
		(*C.char)(tamTokenBin),
		C.size_t(len(tamToken)),
		&out_qResBin[0],
		&out_qResBinLen,
		&out_emptyBin[0],
		&out_emptyBinLen,
		TA_CREATE_QUERY_RESPONSE)

	if rc != 0 {
		log.Fatalf("ERROR")
	}

	queryResponseBin := C.GoBytes(unsafe.Pointer(&out_qResBin), C.int(out_qResBinLen))

	return queryResponseBin
}
