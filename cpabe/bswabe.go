package cpabe

import (
	"github.com/Nik-U/pbc"
	"crypto/sha1"
	"strings"
	"strconv"
	"fmt"
)

type CT struct {
	key *pbc.Element
	s *pbc.Element	 /* Z_r */
	cs *pbc.Element  /* G_T */
	c *pbc.Element	 /* G_1 */
	p *Policy
}

type ElementBoolean struct {
	e *pbc.Element
	b bool
}

type Mk struct {
	beta *pbc.Element  	 /* Z_r */
	g_alpha *pbc.Element  /* G_2 */
}

type Policy struct {
	k int					/* k=1 if leaf, otherwise threshould */
	attr string				/* attribute string if leaf, otherwise null */
	c *pbc.Element			/* G_1 only for leaves */
	cp *pbc.Element			/* G_1 only for leaves */
	children []*Policy
	q *Polynomial
	satisfiable bool
}

type Polynomial struct {
	deg int
	/* coefficients from [0] x^0 to [deg] x^deg */
	coef []*pbc.Element /* G_T (of length deg+1) */
}

type SK struct {
	/*
	 * A private key
	 */
	d *pbc.Element  /* G_2 */
	r *pbc.Element
	comps []BswabePrvComp /* BswabePrvComp */
}

type BswabePrvComp struct {
	/* these actually get serialized */
	attr string
	d *pbc.Element					/* G_2 */
	dp *pbc.Element 				/* G_2 */
}

type PK struct {
	/*
	 * A public key
	 */
	pairingDesc string
	p *pbc.Pairing
	g *pbc.Element				/* G_1 */
	h *pbc.Element				/* G_1 */
	f *pbc.Element				/* G_1 */
	g_hat_alpha *pbc.Element		/* G_T */
}

var curveParams string = "type a\n" + "q 87807107996633125224377819847540498158068831994142082" + "1102865339926647563088022295707862517942266222142315585" + "8769582317459277713367317481324925129998224791\n" + "h 12016012264891146079388821366740534204802954401251311" + "822919615131047207289359704531102844802183906537786776\n" + "r 730750818665451621361119245571504901405976559617\n" + "exp2 159\n" + "exp1 107\n" + "sign1 1\n" + "sign0 1\n"

func Setup(pub *PK, msk *Mk ) {
	params := new(pbc.Params)
	params,_ = pbc.NewParamsFromString(curveParams)

	pub.pairingDesc = curveParams
	pub.p = pbc.NewPairing(params) //G0
	pairing := pub.p

	pub.g = pairing.NewG1().Rand() //g
	pub.f = pairing.NewG1()
	pub.h = pairing.NewG1()
	pub.g_hat_alpha = pairing.NewGT()

	alpha := pairing.NewZr().Rand()
	msk.beta = pairing.NewZr().Rand() //beta
	msk.g_alpha = pairing.NewG2()

	msk.g_alpha = pub.g.ThenPowZn(alpha) //g_alpha
	beta_inv := msk.beta.ThenInvert()
	pub.f = pub.g.ThenPowZn(beta_inv) //f
	pub.h = pub.g.ThenPowZn(msk.beta) //h

	pub.g_hat_alpha.Pair(pub.g,pub.g)
	pub.g_hat_alpha.PowZn(pub.g_hat_alpha,alpha) //e(g,g)^alpha
}

func Keygen(pub *PK, msk *Mk, attrs []string) *SK {
	var prv = new(SK)

	/* initialize */
	pairing := pub.p
	prv.d = pairing.NewG2()
	g_r := pairing.NewG2()
	prv.r = pairing.NewZr().Rand()

	/* compute */
	g_r = pub.g.ThenPowZn(prv.r)

	beta_inv := msk.beta.ThenInvert()
	prv.d = msk.g_alpha.ThenMul(g_r).ThenPowZn(beta_inv) //SK.D = g^((alpha+r)/beta)

	for i := 0; i < len(attrs); i++ {
		var comp = new(BswabePrvComp)
		comp.attr = attrs[i]

		comp.d = pairing.NewG2()
		comp.dp = pairing.NewG1()
		h_rp := pairing.NewG2()

		rp := pairing.NewZr().Rand()

		ElementFromString(h_rp, comp.attr)
		h_rp.PowZn(h_rp,rp)

		comp.d = g_r.ThenMul(h_rp)
		comp.dp = pub.g.ThenPowZn(rp)

		prv.comps = append(prv.comps, *comp)
	}
	return prv
}

func Enc( pub *PK, policy string) *CT {
	cph := new(CT)

	/* initialize */
	pairing := pub.p
	s := pairing.NewZr().Rand()
	m := pairing.NewGT().Rand()
	cph.cs = pairing.NewGT()
	cph.c = pairing.NewG1()
	cph.s = s

	cph.p = parsePolicyPostfix(policy)

	/* compute */
	cph.cs = pub.g_hat_alpha.ThenPowZn(s).ThenMul(m)
	cph.c = pub.h.ThenPowZn(s)

	fillPolicy(cph.p, pub, s)
	cph.key = m

	return cph
}

func Dec( pub *PK, prv *SK, cph *CT) *ElementBoolean {
	beb := new(ElementBoolean)
	m := pub.p.NewGT()
	t := pub.p.NewGT()
	a := pub.p.NewGT()

	checkSatisfy(cph.p, prv) //检查属性集是否满足访问结构policy
	if !cph.p.satisfiable {
		fmt.Println("cannot decrypt, attributes in key do not satisfy policy")
		beb.e = nil
		beb.b = false
		return beb
	}



	a.Pair(pub.g,pub.g).ThenPowZn(prv.r).ThenPowZn(cph.s)
	m = cph.cs.ThenMul(t)

	t.Pair(cph.c, prv.d)
	m.ThenDiv(t)

	beb.e = m
	beb.b = true
	return beb
}

func checkSatisfy( p *Policy, prv *SK) {
	var i, l int
	//var prvAttr string

	p.satisfiable = false
	if p.children == nil || len(p.children) == 0 {
		for i = 0; i < len(prv.comps); i++ {
			tokp := strings.Split(prv.comps[i].attr, "=")
			keyp, valuep := tokp[0], tokp[1]

			if strings.Contains(p.attr, "="){ //需要满足某个属性等于某个值
				toks:= strings.Split(p.attr, "=")
				key, value := toks[0],toks[1]
				if strings.Compare(key, keyp)==0 && strings.Compare(value,valuep)==0 {
					p.satisfiable = true
					break
				}
			} else if strings.Contains(p.attr, "<") {
				toks:= strings.Split(p.attr, "<")
				key, value := toks[0],toks[1]
				if strings.Compare(keyp, key)==0 {
					valuepi,err := strconv.Atoi(valuep)
					valuei,err := strconv.Atoi(value)
					if err != nil {
						fmt.Println("字符串转换成整数失败")
					}
					if valuepi < valuei{
						p.satisfiable = true
						break
					}
				}
			} else {
				toks:= strings.Split(p.attr, ">")
				key, value := toks[0],toks[1]
				if strings.Compare(keyp, key)==0 {
					valuepi,err := strconv.Atoi(valuep)
					valuei,err := strconv.Atoi(value)
					if err != nil {
						fmt.Println("字符串转换成整数失败")
					}
					if valuepi > valuei{
						p.satisfiable = true
						break
					}
				}
			}
		}
	} else {
		for i = 0; i < len(p.children); i++ {
			checkSatisfy(p.children[i], prv)
		}
		l = 0
		for i = 0; i < len(p.children); i++ {
			if p.children[i].satisfiable {
				l++
			}
		}
		if l >= p.k {
			p.satisfiable = true
		}
	}
}

func fillPolicy( p *Policy, pub *PK, s *pbc.Element) {
	pairing := pub.p
	r := pairing.NewZr()
	t := pairing.NewZr()
	h := pairing.NewG2()

	p.q = randPoly(p.k - 1, s)

	if p.children == nil || len(p.children) == 0 {
		p.c = pairing.NewG1()
		p.cp = pairing.NewG2()

		p.c = pub.g.ThenPowZn(p.q.coef[0])
		ElementFromString(h, p.attr)
		p.cp = h.ThenPowZn(p.q.coef[0])
	} else {
		for i := 0; i < len(p.children); i++ {
			r.SetInt32(int32(i + 1))
			evalPoly(t, p.q, r)
			fillPolicy(p.children[i], pub, t)
		}
	}
}

func evalPoly( r *pbc.Element, q *Polynomial, x *pbc.Element) {
	s := r
	t := r

	r.Set0()
	t.Set1()

	for i := 0; i < q.deg + 1; i++ {
		/* r += q->coef[i] * t */
		s = q.coef[i].ThenMul(t)
		r.Add(r,s)

		/* t *= x */
		t.ThenMul(x)
	}
}

func randPoly( deg int, zeroVal *pbc.Element) *Polynomial {
	q := new(Polynomial)
	q.deg = deg
	q.coef = make([]*pbc.Element,deg+1)

	for i := 0; i < deg + 1; i++ {
		q.coef[i] = zeroVal
	}

	q.coef[0].Set(zeroVal)
	for i := 1; i < deg + 1; i++ {
		q.coef[i].Rand()
	}
	return q
}

func parsePolicyPostfix(s string) *Policy {
	var toks []string
	var tok string
	var stack []*Policy
	var root *Policy

	toks = strings.Split(s," ")

	toks_cnt := len(toks)
	for index := 0; index < toks_cnt; index++ {
		var i int

		tok = toks[index]
		if !strings.Contains(tok,"of") {
			//stack.add(baseNode(1, tok))
			stack = append(stack, baseNode(1, tok))
		} else {
			var node *Policy

			/* parse kof n node */
			var k_n []string = strings.Split(tok,"of")
			k,error := strconv.Atoi(k_n[0])
			n,error := strconv.Atoi(k_n[1])
			if error != nil {
				fmt.Println("字符串转换成整数失败")
			}

			if k < 1 {
				fmt.Println("error parsing " + s + ": trivially satisfied operator " + tok)
				return nil
			} else if k > n {
				fmt.Println("error parsing " + s + ": unsatisfiable operator " + tok)
				return nil
			} else if n == 1 {
				fmt.Println("error parsing " + s + ": indentity operator " + tok)
				return nil
			} else if n > len(stack) {
				fmt.Println("error parsing " + s + ": stack underflow at " + tok)
				return nil
			}

			/* pop n things and fill in children */
			node = baseNode(k, "")
			node.children = make([]*Policy,n)

			for i = n - 1; i >= 0; i-- {
				node.children[i] = stack[len(stack)-1]
				stack = stack[:len(stack)-1]
			}
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

func baseNode( k int, s string) *Policy {
	p := new(Policy)
	p.k = k
	p.attr = s
	p.q = nil
	return p
}

func ElementFromString( h *pbc.Element, s string) {
	sha := sha1.Sum([]byte(s))
	var digest = sha[:]
	h.SetFromHash(digest)
}
