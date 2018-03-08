package main

import (
	"fmt"
	"github.com/zrynuaa/cpabe06/bswabe"
)

func main()  {
	pub := new(bswabe.BswabePub)
	msk := new(bswabe.BswabeMsk)
	bswabe.CP_Setup(pub,msk)

	attrs := "foo fim baf"
	prv := bswabe.CP_Keygen(pub,msk,attrs)

	policy := "foo bar fim 2of3 baf 1of2"
	M := "This is test message!"
	keyCph := bswabe.CP_Enc(pub,M,policy)


	result := bswabe.CP_Dec(pub,prv,keyCph)
	fmt.Print("\nresult: " + string(result))
}
