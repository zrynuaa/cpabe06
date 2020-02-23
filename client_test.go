package main

import (
	"fmt"
	"testing"
)

func TestAll(t *testing.T) {
	attrs1 := "abc def hij"
	attrs2 := "abc def klm"
	prv1 := Getsk(attrs1)
	prv2 := Getsk(attrs2)

	policy := "abc hij none 2of3 klm 1of2"
	M := "This is test message!"
	ct := Enc(M,policy)


	result1 := Dec(string(prv1), string(ct))
	fmt.Println("result1: " + string(result1))

	result2 := Dec(string(prv2), string(ct))
	fmt.Println("result2: " + string(result2))
}
