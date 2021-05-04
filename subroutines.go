package pqringct

// rpulpProve generates balance proof
type RpUlpType uint8

const (
	RpUlpTypeCbTx1 RpUlpType = 0
	RpUlpTypeCbTx2 RpUlpType = 1
	RpUlpTypeTrTx1 RpUlpType = 2
	RpUlpTypeTrTx2 RpUlpType = 3
)

/**
cmt_bs []*PolyNTTVec, cmt_cs []*PolyNTT, cmt_rs []*PolyNTTVec: cmt_bs[i] = matrixB * cmt_rs[i], cmt_cs[i] =<matrixC[0], cmt_rs[i]> + (msg_hats[i])_NTT, where msg_hats[i] is viewd as a PolyNTT
h_hat *PolyNTTVec, r_hat *PolyNTTVec, c_hats []*PolyNTT
n >= 2 && n <= n1 && n1 <= n2 && n <= pp.paramI+pp.paramJ && n2 <= pp.paramI+pp.paramJ+4
*/
func (pp PublicParameter) rpulpProve(cmt_bs []*PolyNTTVec, cmt_cs []*PolyNTT, cmt_rs []*PolyNTTVec, n int,
	b_hat *PolyNTTVec, r_hat *PolyNTTVec, c_hats []*PolyNTT, msg_hats [][]int32, n2 int,
	n1 int, rpulpType RpUlpType, B [][]int32, I int, J int, u_hats [][]int32) (err error) {

	c_waves := make([]*PolyNTT, n)
	for i := 0; i < n; i++ {
		c_waves[i] = pp.PolyNTTAdd(pp.PolyNTTVecInnerProduct(pp.paramMatrixC[i+1], cmt_rs[i], pp.paramLc), &PolyNTT{msg_hats[i]})
	}

rpUlpProveRestart:

	cmt_ys := make([][]*PolyNTTVec, pp.paramK)
	ys := make([]*PolyNTTVec, pp.paramK)
	cmt_ws := make([][]*PolyNTTVec, pp.paramK)
	ws := make([]*PolyNTTVec, pp.paramK)
	for t := 0; t < pp.paramK; t++ {
		cmt_ys[t] = make([]*PolyNTTVec, n)
		cmt_ws[t] = make([]*PolyNTTVec, n)
		for i := 0; i < n; i++ {
			cmt_ys[t][i] = pp.NTTVec(pp.sampleMaskC())
			cmt_ws[t][i] = pp.PolyNTTMatrixMulVector(pp.paramMatrixB, cmt_ys[t][i], pp.paramKc, pp.paramLc)
		}

		ys[t] = pp.NTTVec(pp.sampleMaskC())
		ws[t] = pp.PolyNTTMatrixMulVector(pp.paramMatrixB, ys[t], pp.paramKc, pp.paramLc)
	}

	g := pp.NTT(pp.sampleUniformPloyWithLowZeros())
	c_hat_g := pp.PolyNTTAdd(pp.PolyNTTVecInnerProduct(pp.paramMatrixC[pp.paramI+pp.paramJ+5], r_hat, pp.paramLc), g)

	seed1 := []byte{} // todo

	goto rpUlpProveRestart

}

// rpulpVerify verify the proof generated by rpulpProve
func rpulpVerify() (valid bool) {
	//TODO: add inputs
	return false
}

// elrsSign genarates authorizing and authentication proof
func elrsSign() (*Signature, *Image) {
	//TODO: add inputs
	return nil, nil
}

// elrsVerify verify the authorizing and authentication proof generated by elrsSign
func elrsVerify() (valid bool) {
	// TODO: add inputs
	return false
}

/**
todo: generate MatrixA from pp.Cstr
*/
func (pp *PublicParameter) ExpandPubMatrixA() (matrixA []*PolyNTTVec) {
	matrix := make([]*PolyNTTVec, pp.paramKa)

	for i := 0; i < pp.paramKa; i++ {
		matrix[i].polyNTTs = make([]*PolyNTT, pp.paramLa)
		// todo
	}

	return matrixA
}

/**
todo: generate MatrixB from pp.Cstr
todo: store the matrices in PP or generate them each time they are generated
*/
func (pp *PublicParameter) ExpandPubMatrixB() (matrixB []*PolyNTTVec) {
	matrix := make([]*PolyNTTVec, pp.paramKc)

	for i := 0; i < pp.paramKa; i++ {
		matrix[i].polyNTTs = make([]*PolyNTT, pp.paramLc)
		// todo
	}

	return matrix
}

func (pp *PublicParameter) ExpandPubMatrixC() (matrixC []*PolyNTTVec) {
	matrix := make([]*PolyNTTVec, pp.paramI+pp.paramJ+7)

	for i := 0; i < pp.paramI+pp.paramJ+7; i++ {
		matrix[i].polyNTTs = make([]*PolyNTT, pp.paramLc)
		// todo
	}

	return matrix
}

/*
todo: expand a seed to a PolyVec with length l_a from (S_r)^d
*/
func (pp *PublicParameter) ExpandRandomnessA(seed []byte) (sp *PolyVec) {

	polys := make([]*Poly, pp.paramLa)
	//	todo
	r := &PolyVec{
		polys: polys,
	}
	return r
}

func (pp *PublicParameter) ExpandRandomnessC(seed []byte) (r *PolyVec) {

	polys := make([]*Poly, pp.paramLc)
	//	todo
	rst := &PolyVec{
		polys: polys,
	}
	return rst
}

func (pp PublicParameter) sampleRandomnessC() (r *PolyVec) {
	polys := make([]*Poly, pp.paramLc)
	//	todo
	rst := &PolyVec{
		polys: polys,
	}
	return rst
}

func (pp PublicParameter) sampleMaskC() (r *PolyVec) {
	polys := make([]*Poly, pp.paramLc)
	//	todo
	rst := &PolyVec{
		polys: polys,
	}
	return rst
}

func (pp PublicParameter) sampleUniformPloyWithLowZeros() (r *Poly) {
	rst := &Poly{} // todo

	return rst
}

func (pp *PublicParameter) PolyNTTVecInnerProduct(a *PolyNTTVec, b *PolyNTTVec, vecLen int) (r *PolyNTT) {
	rst := NewZeroPolyNTT()
	for i := 0; i < vecLen; i++ {
		rst = pp.PolyNTTAdd(rst, pp.PolyNTTMul(a.polyNTTs[i], b.polyNTTs[i]))
	}

	return rst
}

func (pp *PublicParameter) PolyNTTMatrixMulVector(M []*PolyNTTVec, vec *PolyNTTVec, rowNum int, vecLen int) (r *PolyNTTVec) {
	rst := &PolyNTTVec{}
	rst.polyNTTs = make([]*PolyNTT, rowNum)
	for i := 0; i < rowNum; i++ {
		rst.polyNTTs[i] = pp.PolyNTTVecInnerProduct(M[i], vec, vecLen)
	}
	return rst
}

func intToBinary(v uint64, bitNum int) (bits []int32) {
	rstbits := make([]int32, bitNum)
	for i := 0; i < bitNum; i++ {
		rstbits[i] = int32((v >> i) & 1)
	}
	return rstbits
}

func expandBinaryMatrix(seed []byte, rownum int, colnum int) (binM [][]int32) {
	// todo: in randomness, we need a method to expandUniformBits()
	//	todo: for binaryMatrxi we may do some optimoztion, e.g. use []byte to denote the matrix directly
	//	so that for a 128*128 matrix, we just need 16*16 bytes rather than 128*128 int32's.

	return
}
