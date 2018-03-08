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
	return sk
}

func CP_Enc(pk *BswabePub, M string, p string) *BswabeCphKey {

	fmt.Println("----------Begin Enc----------")
	keyCph := Enc(pk,p)
	fmt.Println("Enc key: ", (keyCph.key.Bytes())[0:32])

	m := []byte(M)
	ciphertext,_ := AES.AesEncrypt(m, (keyCph.key.Bytes())[0:32])
	keyCph.ciphertext = ciphertext

	return keyCph
}

func CP_Dec(pk *BswabePub, sk *BswabePrv, keyCph *BswabeCphKey) []byte {

	fmt.Println("----------Begin Dec----------")
	beb := Dec(pk,sk,keyCph.cph)
	if !beb.b {
		fmt.Println("Policy unmatched!\n")
		return nil
	}

	fmt.Println("Dec key: ", (beb.e.Bytes())[0:32])
	result,_ := AES.AesDecrypt(keyCph.ciphertext, (beb.e.Bytes())[0:32])
	return result
}
