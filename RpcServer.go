package main

import (
	"net/rpc"
	"net/http"
	"fmt"
	"github.com/zrynuaa/cpabe06/bswabe"
)

type CPABE int
var pub *bswabe.BswabePub
var msk *bswabe.BswabeMsk


func (c *CPABE)Getpub(args string, reply *[]byte) error {
	pubdata := bswabe.SerializeBswabePub(pub)
	*reply = pubdata
	return nil
}

func (c *CPABE)Getsk(args string, reply *[]byte) error {
	prv := bswabe.CP_Keygen(pub, msk, args)
	prvdata := bswabe.SerializeBswabePrv(prv)
	*reply = prvdata
	return nil
}

//func (c *CPABE)Enc(args *Encdata, reply *[]byte) error {
//	return nil
//}
//
//func (c *CPABE)Dec(args *Decdata, reply *[]byte) error {
//	return nil
//}

func main()  {
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


