package main

import (
	"fmt"
	"github.com/zrynuaa/cpabe06/bswabe"
)

func main()  {
	pub := new(bswabe.BswabePub)
	msk := new(bswabe.BswabeMsk)
	bswabe.CP_Setup(pub,msk)

	attrs1 := "foo fim baf"
	attrs2 := "foo fim baf"
	prv1 := bswabe.CP_Keygen(pub,msk,attrs1)
	prv2 := bswabe.CP_Keygen(pub,msk,attrs2)

	policy := "foo bar fim 2of3 baf 1of2"
	M := "This is test message!"
	keyCph := bswabe.CP_Enc(pub,M,policy)


	result1 := bswabe.CP_Dec(pub,prv1,keyCph)
	fmt.Println("\nresult1: " + string(result1))

	result2 := bswabe.CP_Dec(pub,prv2,keyCph)
	fmt.Println("\nresult2: " + string(result2))
}
