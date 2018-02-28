package cpabe

import (
	"strings"
	"github.com/Doresimon/ABE/AES"
	"fmt"
)

type Cipher struct {
	ciphertext []byte
	ct *CT
}

func CP_Setup(pk *PK, mk *Mk)  {
	Setup(pk,mk)
}

func CP_Keygen(pk *PK, mk *Mk, attrs string) *SK {
	attr := strings.Split(attrs, " ")
	sk := Keygen(pk, mk, attr)
	return sk
}

func CP_Enc(pk *PK, M string, p string) *Cipher {
	cipher := new(Cipher)
	cipher.ct = Enc(pk,p)
	fmt.Println("\nkey_enc: ")
	fmt.Println((cipher.ct.key.Bytes())[0:32])

	m := []byte(M)
	ciphertext,err := AES.AesEncrypt(m, (cipher.ct.key.Bytes())[0:32])
	cipher.ciphertext = ciphertext
	if err!=nil {
		fmt.Printf("AES Error\n")
	}
	return cipher
}

func CP_Dec(pk *PK, sk *SK, cipher *Cipher) []byte {
	beb := Dec(pk,sk,cipher.ct)
	if !beb.b {
		fmt.Println("Policy unmatched!\n")
		return nil
	}
	fmt.Println("key_dec: ")
	fmt.Println((beb.e.Bytes())[0:32])

	//result,err := AES.AesDecrypt(cipher.ciphertext, (beb.e.Bytes())[0:32])
	result,err := AES.AesDecrypt(cipher.ciphertext, (cipher.ct.key.Bytes())[0:32])
	if err!=nil {
		fmt.Printf("AES Error\n")
	}

	return result
}
