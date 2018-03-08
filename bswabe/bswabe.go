package bswabe

import (
	"github.com/Nik-U/pbc"
	"fmt"
	"strings"
	"strconv"
	"crypto/sha1"
)

type BswabePub struct{
	/*
	 * A public key
	 */
	pairingDesc string
	p *pbc.Pairing
	g *pbc.Element				/* G_1 */
	h *pbc.Element				/* G_1 */
	f *pbc.Element				/* G_1 */
	//gp *pbc.Element				/* G_2 */
	g_hat_alpha *pbc.Element	/* G_T */
}

type BswabeMsk struct{
	/*
	 * A master secret key
	 */
	beta *pbc.Element 			/* Z_r */
	g_alpha *pbc.Element 		/* G_2 */
}

type BswabePrv struct{
	/*
	 * A private key
	 */
	r *pbc.Element
	d *pbc.Element				/* G_2 */
	comps []*BswabePrvComp 		/* BswabePrvComp */
}

type BswabePrvComp struct{
	attr string
	d *pbc.Element				/* G_2 */
	dp *pbc.Element				/* G_2 */

	/* only used during dec */
	used int
	z *pbc.Element				/* G_1 */
	zp *pbc.Element				/* G_1 */
}

type BswabePolynomial struct{
	deg int
	/* coefficients from [0] x^0 to [deg] x^deg */
	coef []*pbc.Element	 		/* G_T (of length deg+1) */
}

type BswabePolicy struct{
	/* k=1 if leaf, otherwise threshould */
	k int
	/* attribute string if leaf, otherwise null */
	attr string
	c *pbc.Element				/* G_1 only for leaves */
	cp *pbc.Element				/* G_1 only for leaves */
	/* array of BswabePolicy and length is 0 for leaves */
	children []*BswabePolicy

	/* only used during encryption */
	q *BswabePolynomial

	/* only used during decription */
	satisfiable bool
	min_leaves int
	attri int
	satl []int
}

type BswabeElementBoolean struct{
	/*
 	* This class is defined for some classes who return both boolean and
 	* Element.
 	*/
	e *pbc.Element
	b bool
}

type BswabeCphKey struct {
	/*
	 * This class is defined for some classes who return both cph and key.
	 */
	ciphertext []byte
	cph *BswabeCph
	key *pbc.Element
}

type BswabeCph struct {
	/*
	 * A ciphertext. Note that this library only handles encrypting a single
	 * group element, so if you want to encrypt something bigger, you will have
	 * to use that group element as a symmetric key for hybrid encryption (which
	 * you do yourself).
	 */
	cs *pbc.Element 		/* G_T */
	c *pbc.Element	 		/* G_1 */
	p *BswabePolicy
	s *pbc.Element
}

/*
	 * Generate a public key and corresponding master secret key.
	 */

var curveParams = "type a\n" +
	"q 87807107996633125224377819847540498158068831994142082"+
		"1102865339926647563088022295707862517942266222142315585"+
			"8769582317459277713367317481324925129998224791\n"+
				"h 12016012264891146079388821366740534204802954401251311"+
					"822919615131047207289359704531102844802183906537786776\n"+
						"r 730750818665451621361119245571504901405976559617\n"+
							"exp2 159\n" + "exp1 107\n" + "sign1 1\n" + "sign0 1\n"

func Setup(pub *BswabePub, msk *BswabeMsk) {
	var alpha, beta_inv *pbc.Element

	params := new(pbc.Params)
	params,_ = pbc.NewParamsFromString(curveParams)
	pub.pairingDesc = curveParams
	pub.p = pbc.NewPairing(params)
	pairing := pub.p

	pub.g = pairing.NewG1()
	pub.f = pairing.NewG1()
	pub.h = pairing.NewG1()
	//pub.gp = pairing.NewG2()
	pub.g_hat_alpha = pairing.NewGT()
	alpha = pairing.NewZr()
	msk.beta = pairing.NewZr()
	msk.g_alpha = pairing.NewG2()

	alpha.Rand()
	msk.beta.Rand()
	pub.g.Rand()
	//pub.gp.Rand()

	//msk.g_alpha = pub.gp.NewFieldElement().Set(pub.gp)
	msk.g_alpha = pub.g.NewFieldElement().Set(pub.g)
	msk.g_alpha.PowZn(msk.g_alpha, alpha)

	beta_inv = msk.beta.NewFieldElement().Set(msk.beta)
	beta_inv.Invert(beta_inv)
	pub.f = pub.g.NewFieldElement().Set(pub.g)
	pub.f.PowZn(pub.f, beta_inv)

	pub.h = pub.g.NewFieldElement().Set(pub.g)
	pub.h.PowZn(pub.h, msk.beta)

	pub.g_hat_alpha.Pair(pub.g, msk.g_alpha)
}

/*
 * Generate a private key with the given set of attributes.
 */
func Keygen(pub *BswabePub,msk *BswabeMsk, attrs []string) *BswabePrv {
	//attrs := strings.Split(attr, " ")

	prv := new(BswabePrv)
	var g_r, r, beta_inv *pbc.Element
	var pairing *pbc.Pairing

	/* initialize */
	pairing = pub.p
	prv.d = pairing.NewG2()
	g_r = pairing.NewG2()
	r = pairing.NewZr()
	beta_inv = pairing.NewZr()

	/* compute */
	r.Rand()
	prv.r = r.NewFieldElement().Set(r)
	//g_r = pub.gp.NewFieldElement().Set(pub.gp)
	g_r = pub.g.NewFieldElement().Set(pub.g)
	g_r.PowZn(g_r, r)

	prv.d = msk.g_alpha.NewFieldElement().Set(msk.g_alpha)
	prv.d.Mul(prv.d, g_r)
	beta_inv = msk.beta.NewFieldElement().Set(msk.beta)
	beta_inv.Invert(beta_inv)
	prv.d.PowZn(prv.d, beta_inv)

	len := len(attrs)
	for i := 0; i < len; i++ {
		comp := new(BswabePrvComp)
		var h_rp, rp *pbc.Element

		comp.attr = attrs[i]
		comp.d = pairing.NewG2()
		comp.dp = pairing.NewG1()
		h_rp = pairing.NewG2()
		rp = pairing.NewZr()

		elementFromString(h_rp, comp.attr)
		rp.Rand()

		h_rp.PowZn(h_rp, rp)

		comp.d = g_r.NewFieldElement().Set(g_r)
		comp.d.Mul(comp.d, h_rp)
		comp.dp = pub.g.NewFieldElement().Set(pub.g)
		comp.dp.PowZn(comp.dp, rp)

		prv.comps = append(prv.comps, comp)
	}
	return prv
}

func Enc(pub *BswabePub, policy string) *BswabeCphKey {
	keyCph := new(BswabeCphKey)
	cph := new(BswabeCph)
	var s, m *pbc.Element

	/* initialize */
	pairing := pub.p;
	s = pairing.NewZr()
	m = pairing.NewGT()
	cph.cs = pairing.NewGT()
	cph.c = pairing.NewG1()
	cph.p = parsePolicyPostfix(policy)

	/* compute */
	m.Rand()
	s.Rand()
	cph.s = s.NewFieldElement().Set(s)
	cph.cs = pub.g_hat_alpha.NewFieldElement().Set(pub.g_hat_alpha)
	cph.cs.PowZn(cph.cs, s) 	/* num_exps++; */
	cph.cs.Mul(cph.cs, m) 		/* num_muls++; */

	cph.c = pub.h.NewFieldElement().Set(pub.h)
	cph.c.PowZn(cph.c, s) 		/* num_exps++; */

	fillPolicy(cph.p, pub, s)

	keyCph.cph = cph
	keyCph.key = m

	return keyCph
}

func Dec(pub *BswabePub, prv *BswabePrv, cph *BswabeCph) *BswabeElementBoolean {
	var t, m *pbc.Element
	beb := new(BswabeElementBoolean)

	m = pub.p.NewGT()
	t = pub.p.NewGT()

	checkSatisfy(cph.p, prv)
	if (!cph.p.satisfiable) {
		fmt.Println("cannot decrypt, attributes in key do not satisfy policy")
		beb.e = nil
		beb.b = false
		return beb
	}

	pickSatisfyMinLeaves(cph.p, prv)
	decFlatten(t, cph.p, prv, pub)

	m = cph.cs.NewFieldElement().Set(cph.cs)
	m.Mul(m, t) 		/* num_muls++; */

	t.Pair(cph.c, prv.d)
	t.Invert(t)
	m.Mul(m, t) 		/* num_muls++; */

	beb.e = m
	beb.b = true
	return beb
}

func decFlatten(r *pbc.Element, p *BswabePolicy, prv *BswabePrv, pub *BswabePub) {
	var one *pbc.Element
	one = pub.p.NewZr()
	one.Set1()
	r.Set1()

	decNodeFlatten(r, one, p, prv, pub)
}

func decNodeFlatten(r *pbc.Element, exp *pbc.Element, p *BswabePolicy, prv *BswabePrv, pub *BswabePub) {
	if p.children == nil || len(p.children) == 0 {
		decLeafFlatten(r, exp, p, prv, pub)
	} else {
		decInternalFlatten(r, exp, p, prv, pub)
	}
}

func decLeafFlatten(r *pbc.Element, exp *pbc.Element, p *BswabePolicy, prv *BswabePrv, pub *BswabePub) {
	c := new(BswabePrvComp)
	var s, t *pbc.Element

	c = prv.comps[p.attri]

	s = pub.p.NewGT()
	t = pub.p.NewGT()

	s.Pair(p.c, c.d) 	/* num_pairings++; */
	t.Pair(p.cp, c.dp) 	/* num_pairings++; */
	t.Invert(t)
	s.Mul(s, t) 		/* num_muls++; */
	s.PowZn(s, exp) 	/* num_exps++; */

	r.Mul(r, s) 		/* num_muls++; */
}

func decInternalFlatten(r *pbc.Element, exp *pbc.Element, p *BswabePolicy, prv *BswabePrv, pub *BswabePub) {
	var i int
	var t, expnew *pbc.Element

	t = pub.p.NewZr()
	expnew = pub.p.NewZr()

	for i = 0; i < len(p.satl); i++ {
		lagrangeCoef(t, p.satl, p.satl[i])
		expnew = exp.NewFieldElement().Set(exp)
		expnew.Mul(expnew, t)
		decNodeFlatten(r, expnew, p.children[p.satl[i] - 1], prv, pub)
	}
}

func lagrangeCoef(r *pbc.Element, s []int, i int) {
	var j, k int
	var t *pbc.Element

	t = r.NewFieldElement().Set(r)

	r.Set1()
	for k = 0; k < len(s); k++ {
		j = s[k]
		if j == i {
			continue
		}
		t.SetInt32(int32(-j))
		r.Mul(r, t) 	/* num_muls++; */
		t.SetInt32(int32(i - j))
		t.Invert(t)
		r.Mul(r, t) 	/* num_muls++; */
	}
}

func pickSatisfyMinLeaves(p *BswabePolicy, prv *BswabePrv) {
	var i, k, l, c_i int
	var c []int

	if p.children == nil || len(p.children) == 0 {
		p.min_leaves = 1
	} else {
		len := len(p.children)
		for i = 0; i < len; i++ {
			if (p.children[i].satisfiable) {
				pickSatisfyMinLeaves(p.children[i], prv)
			}
		}

		for i = 0; i < len; i++ {
			c = append(c, i)
		}

		//TODO 这里的排序需要进一步改写,min_leaves是从小到大排序的，用了很low的冒泡排序。。。
		for i := 0; i < len; i++ {
			for j := 0; j < len-i-1; j++ {
				if p.children[c[j]].min_leaves > p.children[c[j+1]].min_leaves {
					c[j], c[j+1] = c[j+1], c[j]
				}
			}
		}

		p.min_leaves = 0
		l = 0

		for i = 0; i < len && l < p.k; i++ {
			c_i = c[i] /* c[i] */
			if p.children[c_i].satisfiable {
				l++
				p.min_leaves += p.children[c_i].min_leaves
				k = c_i + 1
				p.satl = append(p.satl, k)
			}
		}
	}
}

func checkSatisfy(p *BswabePolicy, prv *BswabePrv) {
	var i, l int
	var prvAttr string

	p.satisfiable = false
	if p.children == nil || len(p.children) == 0 {
	for i = 0; i < len(prv.comps); i++ {
		prvAttr = prv.comps[i].attr
		if strings.Compare(prvAttr,p.attr) == 0 {
			p.satisfiable = true
			p.attri = i
			break
		}
	}
	} else {
		for i = 0; i < len(p.children); i++ {
			checkSatisfy(p.children[i], prv)
		}

		l = 0;
		for i = 0; i < len(p.children); i++ {
			if (p.children[i].satisfiable) {
				l++;
			}
		}

		if (l >= p.k) {
			p.satisfiable = true
		}
	}
}

func fillPolicy(p *BswabePolicy, pub *BswabePub, e *pbc.Element) {
	var i int
	var r, t, h *pbc.Element
	pairing := pub.p
	r = pairing.NewZr()
	t = pairing.NewZr()
	h = pairing.NewG2()

	p.q = randPoly(p.k - 1, e)

	if p.children == nil || len(p.children) == 0 {
		p.c = pairing.NewG1()
		p.cp = pairing.NewG2()

		elementFromString(h, p.attr)
		p.c = pub.g.NewFieldElement().Set(pub.g)
		p.c.PowZn(p.c, p.q.coef[0])
		p.cp = h.NewFieldElement().Set(h)
		p.cp.PowZn(p.cp, p.q.coef[0])
	} else {
		for i = 0; i < len(p.children); i++ {
			r.SetInt32(int32(i + 1))
			evalPoly(t, p.q, r)
			fillPolicy(p.children[i], pub, t)
		}
	}

}

func evalPoly(r *pbc.Element, q *BswabePolynomial, x *pbc.Element) {
	var i int
	var s, t *pbc.Element

	s = r.NewFieldElement().Set(r)
	t = r.NewFieldElement().Set(r)

	r.Set0()
	t.Set1()

	for i = 0; i < q.deg + 1; i++ {
		/* r += q->coef[i] * t */
		s = q.coef[i].NewFieldElement().Set(q.coef[i])
		s.Mul(s, t)
		r.Add(r, s)

		/* t *= x */
		t.Mul(t, x)
	}

}

func randPoly(deg int, zeroVal *pbc.Element) *BswabePolynomial {
	var i int
	q := new(BswabePolynomial)
	q.deg = deg
	q.coef = make([]*pbc.Element, deg+1)

	for i = 0; i < deg+1; i++ {
		q.coef[i] = zeroVal.NewFieldElement().Set(zeroVal)
	}

	q.coef[0].Set(zeroVal)

	for i = 1; i < deg+1; i++ {
		q.coef[i].Rand()
	}

	return q;
}

func parsePolicyPostfix(s string) *BswabePolicy {
	var toks []string
	var tok string
	var stack []*BswabePolicy
	var root *BswabePolicy

	toks = strings.Split(s, " ")

	toks_cnt := len(toks)
	for index := 0; index < toks_cnt; index++ {
		var i, k, n int

		tok = toks[index]
		if !strings.Contains(tok, "of") {
			stack = append(stack, baseNode(1, tok))
		} else {
			var node *BswabePolicy

			/* parse k of n node */
			k_n := strings.Split(tok, "of")
			k,_ = strconv.Atoi(k_n[0])
			n,_ = strconv.Atoi(k_n[1])

			if k < 1 {
				fmt.Println("error parsing " + s + ": trivially satisfied operator " + tok)
				return nil
			} else if k > n {
				fmt.Println("error parsing " + s + ": unsatisfiable operator " + tok)
				return nil
			} else if n == 1 {
				fmt.Println("error parsing " + s+ ": indentity operator " + tok)
				return nil
			} else if n > len(stack) {
				fmt.Println("error parsing " + s + ": stack underflow at " + tok)
				return nil
			}

			/* pop n things and fill in children */
			node = baseNode(k, "")
			node.children = make([]*BswabePolicy,n)

			for i = n - 1; i >= 0; i-- {
				node.children[i] = stack[len(stack) - 1]
				stack = stack[:len(stack)-1]
			}

			/* push result */
			stack = append(stack, node)
		}
	}

	if len(stack) > 1 {
		fmt.Println("error parsing " + s + ": extra node left on the stack")
		return nil
	} else if len(stack) < 1 {
		fmt.Println("error parsing " + s + ": empty policy")
		return nil
	}

	root = stack[0]
	return root
}

func baseNode(k int, s string) *BswabePolicy {
	p := new(BswabePolicy)

	p.k = k
	if !(s == "") {
		p.attr = s
	} else {
		p.attr = ""
	}
	p.q = nil

	return p
}

func elementFromString(h *pbc.Element, s string) {
	sha := sha1.Sum([]byte(s))
	digest := sha[:]
	h.SetFromHash(digest)
}
