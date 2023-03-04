package tee

// #include "tee_interface.h"
// #include "stdlib.h"
import "C"

import (
	"log"
	"unsafe"
)

const TA_CREATE_EVIDENCE = 1
const TA_CREATE_QUERY_RESPONSE = 2
const BUFF_SIZE = 1024

func reqTeepAgent(comId uint32, in1 []byte, in2 []byte) ([]byte, []byte) {
	c_in1 := C.CBytes(in1)
	c_in1_len := C.size_t(len(in1))
	defer C.free(unsafe.Pointer(c_in1))

	c_in2 := C.CBytes(in2)
	c_in2_len := C.size_t(len(in2))
	defer C.free(unsafe.Pointer(c_in2))

	var c_out_buf1 [BUFF_SIZE]C.char
	var c_out_buf1_len C.size_t
	var c_out_buf2 [BUFF_SIZE]C.char
	var c_out_buf2_len C.size_t

	rc := C.invoke_teep_agent(
		(*C.char)(c_in1), c_in1_len,
		(*C.char)(c_in2), c_in2_len,
		&c_out_buf1[0], &c_out_buf1_len,
		&c_out_buf2[0], &c_out_buf2_len,
		C.uint(comId))
	if rc != 0 {
		log.Fatalf("ERROR")
	}

	out1 := C.GoBytes(unsafe.Pointer(&c_out_buf1), C.int(c_out_buf1_len))
	out2 := C.GoBytes(unsafe.Pointer(&c_out_buf2), C.int(c_out_buf2_len))

	return out1, out2
}

func CreateEvidence(queryRequest []byte, verifierNonce []byte) ([]byte, []byte) {
	evidence, tamToken := reqTeepAgent(TA_CREATE_EVIDENCE, queryRequest, verifierNonce)
	return evidence, tamToken
}

func CreateQueryResponse(attRes []byte, tamToken []byte) []byte {
	queryResponse, _ := reqTeepAgent(TA_CREATE_QUERY_RESPONSE, attRes, tamToken)
	return queryResponse
}
