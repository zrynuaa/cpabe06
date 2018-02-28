package main

import (
	"fmt"
	"CPABE06/bswabe"
)

func main()  {

	//Setup
	pk := new(cpabe.PK)
	mk := new(cpabe.Mk)
	cpabe.CP_Setup(pk,mk)

	//Keygen
	attrs := "name=roy age=24 salary=10"
	sk := cpabe.CP_Keygen(pk,mk,attrs)
	//fmt.Println(sk)

	//enc
	m := "This is test message!" //message
	policy := "name=roy age<25 class=17 2of3 salary>10 1of2"
	ct := cpabe.CP_Enc(pk,m,policy)
	//fmt.Println(ct)

	//dec
	//beb := new(cpabe.ElementBoolean)
	result := cpabe.CP_Dec(pk,sk,ct)
	fmt.Println("Dec result: " + string(result[:]))
}
