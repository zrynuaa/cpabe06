package bswabe

import (
"strings"
//"github.com/Doresimon/ABE/AES"
"fmt"
)

func CP_Setup(pk *BswabePub, mk *BswabeMsk)  {
	Setup(pk,mk)
}

func CP_Keygen(pk *BswabePub, mk *BswabeMsk, attrs string) *BswabePrv {
	attr := strings.Split(attrs, " ")
	sk := Keygen(pk, mk, attr)
	return sk
}

func CP_Enc(pk *BswabePub, M string, p string) *BswabeCphKey {

	fmt.Println("----------Begin Enc----------")
	keyCph, key := Enc(pk,p)
	fmt.Println("Enc key: ", (key.Bytes())[0:32])

	m := []byte(M)
	ciphertext,_ := AesEncrypt(m, (key.Bytes())[0:32])
	keyCph.ciphertext = ciphertext

	return keyCph
}

func CP_Dec(pk *BswabePub, sk *BswabePrv, keyCph *BswabeCphKey) []byte {

	fmt.Println("----------Begin Dec----------")
	beb := Dec(pk,sk,keyCph.Cph)
	if !beb.B {
		fmt.Println("Policy unmatched!")
		return nil
	}

	fmt.Println("Dec key: ", (beb.E.Bytes())[0:32])
	result,_ := AesDecrypt(keyCph.ciphertext, (beb.E.Bytes())[0:32])
	return result
}