package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/gin-gonic/gin"
	"github.com/veraison/go-cose"
)

// postVerify
func postVerify(c *gin.Context) {
	// Call BindJSON to bind the received JSON to
	// newAlbum.
	evidence, err := c.GetRawData()
	if err != nil {
		fmt.Println("Erro: ", err)
	}

	privateKey := createPrivateKey()

	err = VerifyP256(privateKey.Public(), evidence)
	if err != nil {
		fmt.Println("verify err = ", err)
	}
	fmt.Println("verify OK.")
	fmt.Println("evidence = ", evidence)
	return
}

func SignP256(data []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	// create a signer
	// privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// if err != nil {
	// 	return nil, err
	// }
	signer, err := cose.NewSigner(cose.AlgorithmES256, privateKey)
	if err != nil {
		return nil, err
	}

	// create message header
	headers := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: cose.AlgorithmES256,
		},
	}

	// sign and marshal message
	return cose.Sign1(rand.Reader, signer, headers, data, nil)
}

type evidence struct {
	Issuer []byte `cbor:"1,keyasint,omitempty"`
	Time   int64  `cbor:"6,keyasint,omitempty"`
	Nonce  []byte `cbor:"10,keyasint,omitempty"`
}

func VerifyP256(publicKey crypto.PublicKey, sig []byte) error {
	// create a verifier from a trusted private key
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, publicKey)
	if err != nil {
		return err
	}

	var msg cose.Sign1Message
	if err = msg.UnmarshalCBOR(sig); err != nil {
		return err
	}

	var v evidence
	err = cbor.Unmarshal(msg.Payload, &v)

	unixTimeUTC := time.Unix(v.Time, 0)                   //gives unix time stamp in utc
	unitTimeInRFC3339 := unixTimeUTC.Format(time.RFC3339) // converts utc time to RFC3339 format

	fmt.Println("Issuer = ", string(v.Issuer[:]))
	fmt.Println("Time = ", unitTimeInRFC3339)
	fmt.Println("Nonce = ", string(v.Nonce[:]))

	// encodedString := hex.EncodeToString(
	// fmt.Println("msg.Payload = ", encodedString)
	// var payload = msg.Payload

	return msg.Verify(nil, verifier)
}

func createPrivateKey() *ecdsa.PrivateKey {
	teep_agent_es256_private_key_R := new(big.Int).SetBytes([]byte{
		0x60, 0xfe, 0x6d, 0xd6, 0xd8, 0x5d, 0x57, 0x40, 0xa5, 0x34, 0x9b,
		0x6f, 0x91, 0x26, 0x7e, 0xea, 0xc5, 0xba, 0x81, 0xb8, 0xcb, 0x53,
		0xee, 0x24, 0x9e, 0x4b, 0x4e, 0xb1, 0x02, 0xc4, 0x76, 0xb3})

	teep_agent_es256_public_key_X := new(big.Int).SetBytes([]byte{
		0x58, 0x86, 0xcd, 0x61, 0xdd, 0x87, 0x58, 0x62, 0xe5, 0xaa, 0xa8,
		0x20, 0xe7, 0xa1, 0x52, 0x74, 0xc9, 0x68, 0xa9, 0xbc, 0x96, 0x04,
		0x8d, 0xdc, 0xac, 0xe3, 0x2f, 0x50, 0xc3, 0x65, 0x1b, 0xa3})

	teep_agent_es256_public_key_Y := new(big.Int).SetBytes([]byte{
		0x9e, 0xed, 0x81, 0x25, 0xe9, 0x32, 0xcd, 0x60, 0xc0, 0xea, 0xd3,
		0x65, 0x0d, 0x0a, 0x48, 0x5c, 0xf7, 0x26, 0xd3, 0x78, 0xd1, 0xb0,
		0x16, 0xed, 0x42, 0x98, 0xb2, 0x96, 0x1e, 0x25, 0x8f, 0x1b})

	var e ecdsa.PrivateKey

	e.D = teep_agent_es256_private_key_R
	e.PublicKey.Curve = elliptic.P256()
	e.PublicKey.X = teep_agent_es256_public_key_X
	e.PublicKey.Y = teep_agent_es256_public_key_Y

	return &e
}

func main() {
	privateKey := createPrivateKey()
	data := []byte{1, 1, 1}
	sig, err := SignP256(data, privateKey)
	if err != nil {
		fmt.Println("sig err = ", err)
	}
	fmt.Println("sig = ", sig)

	err = VerifyP256(privateKey.Public(), sig)
	if err != nil {
		fmt.Println("verify err = ", err)
	}

	router := gin.Default()
	router.POST("/verify", postVerify)
	router.Run("localhost:8080")
}
