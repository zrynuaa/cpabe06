package bswabe

import (
	"strings"
	"github.com/Doresimon/ABE/AES"
	"fmt"
)

func CP_Setup(pk *BswabePub, mk *BswabeMsk)  {
	Setup(pk,mk)
}

func CP_Keygen(pk *BswabePub, mk *BswabeMsk, attrs string) *BswabePrv {
	attr := strings.Split(attrs, " ")
	sk := Keygen(pk, mk, attr)
	//for i := 0; i<len(attr); i++{
	//	fmt.Println("d",i ,": " ,sk.comps[i].d.Bytes())
	//	fmt.Println("dp",i ,": " ,sk.comps[i].dp.Bytes())
	//}

	//fmt.Println(sk.d.Bytes())
	//fmt.Println(sk.comps[0].d.Bytes())
	return sk
}

func CP_Enc(pk *BswabePub, M string, p string) *BswabeCphKey {

	fmt.Println("\n----------Begin Enc----------")
	cipherkey := Enc(pk,p)

	fmt.Println("c1:",cipherkey.cph.p.children[0].children[0].c.Bytes())
	fmt.Println("cp1:",cipherkey.cph.p.children[0].children[0].cp.Bytes())
	//fmt.Println("cp1:",cipherkey.cph.p.children[0].cp.Bytes())
	//fmt.Println("c2:",cipherkey.cph.p.children[1].c.Bytes())
	//fmt.Println("cp2:",cipherkey.cph.p.children[1].cp.Bytes())

	m := []byte(M)
	ciphertext,_ := AES.AesEncrypt(m, (cipherkey.key.Bytes())[0:32])

	fmt.Println("Enc key: ", (cipherkey.key.Bytes())[0:32])
	cipherkey.ciphertext = ciphertext
	//fmt.Print("ciphertext: ")
	//fmt.Println(ciphertext)

	return cipherkey
}

func CP_Dec(pk *BswabePub, sk *BswabePrv, cipherkey *BswabeCphKey) []byte {

	fmt.Println("\n----------Begin Dec----------")
	//for i := 0; i<len(sk.comps); i++{
	//	fmt.Println("d",i ,": " ,sk.comps[i].d.Bytes())
	//	fmt.Println("dp",i ,": " ,sk.comps[i].dp.Bytes())
	//}
	//fmt.Println("c1:",cipherkey.cph.p.children[0].c.Bytes())
	//fmt.Println("cp1:",cipherkey.cph.p.children[0].cp.Bytes())
	//fmt.Println("c2:",cipherkey.cph.p.children[1].c.Bytes())
	//fmt.Println("cp2:",cipherkey.cph.p.children[1].cp.Bytes())


	beb := Dec(pk,sk,cipherkey.cph)
	if !beb.b {
		fmt.Println("Policy unmatched!\n")
		return nil
	}

	fmt.Println("Dec key: ", (beb.e.Bytes())[0:32])

	result,_ := AES.AesDecrypt(cipherkey.ciphertext, (beb.e.Bytes())[0:32])
	//result,err := AES.AesDecrypt(cipher.ciphertext, (cipher.ct.key.Bytes())[0:32])

	return result
}
