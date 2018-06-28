package bswabe

import "github.com/Nik-U/pbc"

type BswabePub struct{
	/*
	 * A public key
	 */
	PairingDesc string `json:"pairing_desc"`
	p *pbc.Pairing `json:"p"`
	g *pbc.Element `json:"g"`			/* G_1 */
	h *pbc.Element `json:"h"`			/* G_1 */
	f *pbc.Element `json:"f"`			/* G_1 */
	gp *pbc.Element `json:"gp"`			/* G_2 */
	g_hat_alpha *pbc.Element `json:"g_hat_alpha"`	/* G_T */
}

type BswabeMsk struct{
	/*
	 * A master secret key
	 */
	beta *pbc.Element `json:"beta"`			/* Z_r */
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
	E *pbc.Element
	B bool
}

type BswabeCphKey struct {
	/*
	 * This class is defined for some classes who return both cph and key.
	 */
	Cph *BswabeCph
	//Key *pbc.Element
	ciphertext []byte
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
