package bswabe

import (
	"github.com/Nik-U/pbc"
)

func serializeElement(arrlist *[]byte, e *pbc.Element) {
	arr_e := e.Bytes()
	serializeUint32(arrlist, len(arr_e))
	*arrlist = append(*arrlist, arr_e...)
}

func unserializeElement(arr []byte, offset int, e *pbc.Element) int {
	len := unserializeUint32(arr, offset)
	e_byte := make([]byte, len)
	offset += 4
	for i := 0; i < len; i++ {
		e_byte[i] = arr[offset+i]
	}
	e.SetBytes(e_byte)

	return offset + len
}

func serializeString(arrlist *[]byte, s string) {
	b := []byte(s)
	serializeUint32(arrlist, len(b))
	*arrlist = append(*arrlist, b...)
}

func unserializeString(arr []byte, offset int, sb *string) int {
	len := unserializeUint32(arr, offset)
	offset += 4
	str_byte := make([]byte, len)
	for i := 0; i < len; i++ {
		str_byte[i] = arr[offset+i]
	}

	*sb += string(str_byte)
	return offset + len
}

func SerializeBswabePub(pub *BswabePub) []byte {
	var arrlist []byte

	serializeString(&arrlist, pub.PairingDesc);
	serializeElement(&arrlist, pub.g);
	serializeElement(&arrlist, pub.h);
	serializeElement(&arrlist, pub.gp);
	serializeElement(&arrlist, pub.g_hat_alpha);

	return arrlist
}

func UnSerializeBswabePub(b []byte) *BswabePub {
	pub := new(BswabePub)
	offset := 0

	sb := ""
	offset = unserializeString(b, offset, &sb)
	pub.PairingDesc = sb

	params := new(pbc.Params)
	params,_ = pbc.NewParamsFromString(pub.PairingDesc)
	//fmt.Println("Unserilize : params: ",params)
	pub.p = pbc.NewPairing(params)
	pairing := pub.p

	pub.g = pairing.NewG1()
	pub.h = pairing.NewG1()
	pub.gp = pairing.NewG2()
	pub.g_hat_alpha = pairing.NewGT()

	offset = unserializeElement(b, offset, pub.g)
	offset = unserializeElement(b, offset, pub.h)
	offset = unserializeElement(b, offset, pub.gp)
	offset = unserializeElement(b, offset, pub.g_hat_alpha)

	return pub
}

func serializeBswabeMsk(msk *BswabeMsk) []byte {
	var arrlist []byte

	serializeElement(&arrlist, msk.beta);
	serializeElement(&arrlist, msk.g_alpha);

	return arrlist
}

func unserializeBswabeMsk(pub *BswabePub, b []byte) *BswabeMsk {
	offset := 0
	msk := new(BswabeMsk)

	msk.beta = pub.p.NewZr()
	msk.g_alpha = pub.p.NewG2()

	offset = unserializeElement(b, offset, msk.beta)
	offset = unserializeElement(b, offset, msk.g_alpha)

	return msk
}

func SerializeBswabePrv(prv *BswabePrv) []byte {
	var arrlist []byte
	prvCompsLen := len(prv.comps)
	serializeElement(&arrlist, prv.d)
	serializeUint32(&arrlist, prvCompsLen)

	for i := 0; i < prvCompsLen; i++ {
		serializeString(&arrlist, prv.comps[i].attr)
		serializeElement(&arrlist, prv.comps[i].d)
		serializeElement(&arrlist, prv.comps[i].dp)
	}

	return arrlist
}

func UnSerializeBswabePrv(pub *BswabePub, b []byte) *BswabePrv {
	prv := new(BswabePrv)
	offset := 0

	prv.d = pub.p.NewG2()
	offset = unserializeElement(b, offset, prv.d)

	len := unserializeUint32(b, offset)
	prv.comps = make([]*BswabePrvComp, len)
	offset += 4

	for i := 0; i < len; i++ {
		c := new(BswabePrvComp)

		sb := ""
		offset = unserializeString(b, offset, &sb)
		c.attr = sb

		c.d = pub.p.NewG2()
		c.dp = pub.p.NewG2()

		offset = unserializeElement(b, offset, c.d)
		offset = unserializeElement(b, offset, c.dp)

		prv.comps[i] = c
	}

	return prv
}

func SerializeBswabeCphKey(cphkey *BswabeCphKey) []byte {
	var arrlist []byte

	BswabeCphSerialize(&arrlist, cphkey.Cph)
	arrlist = append(arrlist, cphkey.ciphertext...)

	return arrlist
}

func UnSerializeBswabeCphKey(pub *BswabePub, cphBuf []byte) *BswabeCphKey {
	cphkey := new(BswabeCphKey)
	var offset int

	cphkey.Cph, offset = BswabeCphUnserialize(pub, cphBuf)
	cphkey.ciphertext = cphBuf[offset:]

	return cphkey
}

func BswabeCphSerialize(arrlist *[]byte, cph *BswabeCph) {
	//var arrlist []byte
	serializeElement(arrlist, cph.cs)
	serializeElement(arrlist, cph.c)
	serializePolicy(arrlist, cph.p)

	//return arrlist
}

func BswabeCphUnserialize(pub *BswabePub, cphBuf []byte) (*BswabeCph, int) {
	cph := new(BswabeCph)
	offset := 0
	offset_arr := make([]int, 1)

	cph.cs = pub.p.NewGT()
	cph.c = pub.p.NewG1()

	offset = unserializeElement(cphBuf, offset, cph.cs)
	offset = unserializeElement(cphBuf, offset, cph.c)

	offset_arr[0] = offset
	cph.p = unserializePolicy(pub, cphBuf, &offset_arr)
	offset = offset_arr[0]

	return cph, offset
}

func serializeUint32(arrlist *[]byte, k int) {
	for i := 3; i >= 0; i-- {
		b := (byte) ((k & (0x000000ff << uint(i * 8))) >> uint(i * 8))
		*arrlist = append(*arrlist, b)
	}
}

func unserializeUint32(arr []byte, offset int) int {
	r := 0

	for i := 3; i >= 0; i-- {
		r |= (int(arr[offset])) << uint(i * 8)
		offset++
	}
	return r
}

func serializePolicy(arrlist *[]byte, p *BswabePolicy) {
	serializeUint32(arrlist, p.k)

	if p.children == nil || len(p.children) == 0 {
		serializeUint32(arrlist, 0)
		serializeString(arrlist, p.attr)
		serializeElement(arrlist, p.c)
		serializeElement(arrlist, p.cp)
	} else {
		serializeUint32(arrlist, len(p.children))
		for i := 0; i < len(p.children); i++ {
			serializePolicy(arrlist, p.children[i])
		}
	}
}

func unserializePolicy(pub *BswabePub, arr []byte, offset *[]int) *BswabePolicy {
	p := new(BswabePolicy)
	p.k = unserializeUint32(arr, (*offset)[0]) //TODO 检查用法是否正确
	(*offset)[0] += 4
	p.attr = ""

	/* children */
	n := unserializeUint32(arr, (*offset)[0])
	(*offset)[0] += 4
		if (n == 0) {
		p.children = nil

		sb := ""
		(*offset)[0] = unserializeString(arr, (*offset)[0], &sb)
		p.attr = sb

		p.c = pub.p.NewG1()
		p.cp = pub.p.NewG1()

		(*offset)[0] = unserializeElement(arr, (*offset)[0], p.c)
		(*offset)[0] = unserializeElement(arr, (*offset)[0], p.cp)
	} else {
		p.children = make([]*BswabePolicy, n)
		for i := 0; i < n; i++ {
			p.children[i] = unserializePolicy(pub, arr, offset)
		}
	}

	return p
}