package main

import (
	"fmt"
	"github.com/zrynuaa/cpabe06/bswabe"
	"net/http"
	"net/rpc"
)

type CPABE int

var pub *bswabe.BswabePub
var msk *bswabe.BswabeMsk

func (c *CPABE) Getpub(args string, reply *[]byte) error {
	pubdata := bswabe.SerializeBswabePub(pub)
	*reply = pubdata
	return nil
}

func (c *CPABE) Getsk(attr string, reply *[]byte) error {
	prv := bswabe.CP_Keygen(pub, msk, attr)
	privateKey := bswabe.SerializeBswabePrv(prv)
	*reply = privateKey
	return nil
}

func (c *CPABE) Enc(args []string, reply *[]byte) error {
	M := args[0]
	policy := args[1]
	keyCph := bswabe.CP_Enc(pub, M, policy)
	data := bswabe.SerializeBswabeCphKey(keyCph)
	*reply = data
	return nil
}

func (c *CPABE) Dec(args []string, reply *[]byte) error {
	privateKey := bswabe.UnSerializeBswabePrv(pub, []byte(args[0]))
	ct := bswabe.UnSerializeBswabeCphKey(pub, []byte(args[1]))
	m := bswabe.CP_Dec(pub, privateKey, ct)
	*reply = m
	return nil
}

func main() {
	pub = new(bswabe.BswabePub)
	msk = new(bswabe.BswabeMsk)
	bswabe.CP_Setup(pub, msk) //setup

	cpabe := new(CPABE)
	rpc.Register(cpabe)
	rpc.HandleHTTP()

	err := http.ListenAndServe(":1234", nil)
	if err != nil {
		fmt.Println(err.Error())
	}
}
