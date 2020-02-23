package main

import (
	"fmt"
	"net/rpc"
)

var RPCADDRESS string = "localhost:1234"

func dial() *rpc.Client {
	client, err := rpc.DialHTTP("tcp", RPCADDRESS)
	if err != nil {
		fmt.Println("dialing:", err)
	}
	return client
}

//Client functions
func Getpub() []byte {
	client := dial()

	args := ""
	var reply []byte
	err := client.Call("CPABE.Getpub", args, &reply)
	if err != nil {
		fmt.Println("CPABE error:", err)
	}

	return reply
}

//Client functions
func Getsk(attr string) []byte {
	client := dial()

	args := attr
	var reply []byte
	err := client.Call("CPABE.Getsk", args, &reply)
	if err != nil {
		fmt.Println("CPABE error:", err)
	}

	return reply
}

//Client functions
func Enc(m, policy string) []byte {
	client := dial()

	args := []string{m, policy}
	var reply []byte
	err := client.Call("CPABE.Enc", args, &reply)
	if err != nil {
		fmt.Println("CPABE error:", err)
	}

	return reply
}

//Client functions
func Dec(privateKey, ct string) []byte {
	client := dial()

	args := []string{privateKey, ct}
	var reply []byte
	err := client.Call("CPABE.Dec", args, &reply)
	if err != nil {
		fmt.Println("CPABE error:", err)
	}

	return reply
}
