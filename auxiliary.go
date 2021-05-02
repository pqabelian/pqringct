package pqringct

// This file provides auxiliary functions for pqringct.go

func txoGen(mpk *MasterPubKey, v int64) (txo *TXO, SrDXLc [][]byte) {
	//	to do
	//	var kappa = [32]byte{}
	//	var ds = expandKa(kappa)
	for i := 0; i < PP_l_a; i++ {

	}
	return nil, nil
}


// expandPubM
func expandPubM(seed []int) (pp PubParams) {
	panic("implement me")
	return PubParams{
		A: []PolyVecANTT{},
		B: []PolyVecCNTT{},
		C: []PolyVecCNTT{},
	}
}

// h is instance of the H function {0,1)* -> {0,1}^slen
func h(data []byte) (digest []byte) {
	panic("implement me") // TODO: will be used sha3.shake256 instantiate
	return nil
}

// expandKA is instance of the K_kem -> S_r^{l_a}
func expandKA(kkem []byte) (SrDXLa [][]byte) {
	//	todo: (S_r)^{l_a}
	panic("implement me")
	return nil
}

// expandKC is instance of the K_kem -> S_r^{l_c}
func expandKC(kkem []byte) (SrDXLc [][]byte) {
	//	todo: (S_r)^{l_a}
	panic("implement me")
	return nil
}

// expandKV is instance of the K_kem -> {0,1}^d
func expandKV(kkem []byte) (UniD []byte) {
	//	todo: {0,1}^d
	panic("implement me")
	return nil
}

// expandKImg is instance of the R_q^{k_a} -> R_q^{m_a X l_a}
func expandKImg(Ka []Poly) (MaXLa [][]Poly) {
	//	todo
	panic("implement me")
	return nil
}

// expandCh is instance of the {0,1}^slen -> S_c
func expandCh(seed []byte) (ScD []byte) {
	//	todo
	panic("implement me")
	return nil
}

// expandRand is instance of the {0,1}^slen X Z+ X Z+ -> R_q^{n_1} X (Z_q^d)^{n_2}
func expandRand(seed []byte, n1 int, n2 int) (RqN1 []Poly, ZqDXN2 [][]int) {
	//	todo
	panic("implement me")
	return nil, nil
}

// expandBinM is instance of the {0,1}^slen X Z+ -> ({0,1}^{d X d})^n
func expandBinM(seed []byte, n int) (DXDXN [][][]int) {
	//	todo
	panic("implement me")
	return nil
}
