package main

import (
	"github.com/zrynuaa/cpabe06/bswabe"
	"fmt"
)

func main() {
	pub := new(bswabe.BswabePub)
	msk := new(bswabe.BswabeMsk)
	var prv, prv_delegate_ok, prv_delegate_ko *bswabe.BswabePrv
	var cph *bswabe.BswabeCph
	var result *bswabe.BswabeElementBoolean

	attr = attr_kevin
	//attr = attr_sara;
	policy = policy_kevin_or_sara

	fmt.Println("//demo for bswabe: start to setup")
	bswabe.Setup(pub, msk)
	fmt.Println("//demo for bswabe: end to setup")

	fmt.Println("\n//demo for bswabe: start to keygen")
	prv = bswabe.Keygen(pub, msk, attr)
	fmt.Println("//demo for bswabe: end to keygen")

	fmt.Println("\n//demo for bswabe: start to delegate_ok")
	prv_delegate_ok = bswabe.Delegate(pub, prv, attr_delegate_ok)
	fmt.Println("//demo for bswabe: end to delegate_ok")

	fmt.Println("\n//demo for bswabe: start to delegate_ko");
	prv_delegate_ko = bswabe.Delegate(pub, prv, attr_delegate_ko)
	fmt.Println("//demo for bswabe: end to delegate_ko")

	fmt.Println("\n//demo for bswabe: start to enc")
	crypted := bswabe.Enc(pub, policy)
	cph = crypted.cph
	fmt.Println("//demo for bswabe: end to enc");
	fmt.Println("\n//demo for bswabe: start to dec")
	result = bswabe.dec(pub, prv, cph)
	println("//demo for bswabe: end to dec")
	if (result.b == true) && (result.e.equals(crypted.key) == true) {
		fmt.Println("succeed in decrypt")
	} else {
		fmt.Println("failed to decrypting")
	}

	fmt.Println("\n//demo for bswabe: start to dec with ok delegated key")
	result = bswabe.Dec(pub, prv_delegate_ok, cph)
	println("//demo for bswabe: end to dec with ok delegated key")
	if (result.b == true) && (result.e.equals(crypted.key) == true) {
		fmt.Println("succeed in decrypt with ok delegated key")
	} else{
		fmt.Println("failed to decrypting with ok delegated key")
	}

	fmt.Println("\n//demo for bswabe: start to dec");
	result = bswabe.Dec(pub, prv, cph)
	fmt.Println("//demo for bswabe: end to dec");
	if (result.b == true) && (result.e.equals(crypted.key) == true) {
		fmt.Println("succeed in decrypt")
	} else {
		fmt.Println("failed to decrypting")
	}

	fmt.Println("\n//demo for bswabe: start to dec with ko delegated key")
	result = bswabe.Dec(pub, prv_delegate_ko, cph)
	println("//demo for bswabe: end to dec with ko delegated key")
	if (result.b == true) && (result.e.equals(crypted.key) == true) {
		fmt.Println("succeed in decrypt with ko delegated key (should not happen)")
	} else {
		fmt.Println("failed to decrypting with ko delegated key")
	}
}
