package pqringct

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"github.com/cryptosuite/pqringct/pqringctkem"
	"log"
	"math/big"
)

type AddressPublicKey struct {
	t *PolyANTTVec // directly in NTT form
	e *PolyANTT
}
type AddressSecretKey struct {
	*AddressSecretKeySp
	*AddressSecretKeySn
}

type AddressSecretKeySp struct {
	s *PolyANTTVec
}
type AddressSecretKeySn struct {
	ma *PolyANTT
}

func (apk *AddressPublicKey) WellformCheck(pp *PublicParameter) bool {
	// todo
	return true
}

func (ask *AddressSecretKey) WellformCheck(pp *PublicParameter) bool {
	// todo
	return true
}

func (ask *AddressSecretKey) CheckMatchPublciKey(apk *AddressPublicKey, pp *PublicParameter) bool {
	// todo As=t, <a,s> + m_a = e
	return true
}

type Txo struct {
	*AddressPublicKey
	*ValueCommitment
	Vct           []byte
	CkemSerialzed []byte
}

func NewTxo(apk *AddressPublicKey, cmt *ValueCommitment, vct []byte, ckem []byte) *Txo {
	return &Txo{
		AddressPublicKey: apk,
		ValueCommitment:  cmt,
		Vct:              vct,
		CkemSerialzed:    ckem,
	}

}

type LgrTxo struct {
	Txo
	Id []byte
}

func NewLgrTxo(txo *Txo, id []byte) *LgrTxo {
	return &LgrTxo{
		Txo: *txo,
		Id:  id,
	}
}

type ValueCommitment struct {
	b *PolyCNTTVec
	c *PolyCNTT
}

type rpulpProofv2 struct {
	c_waves []*PolyCNTT
	c_hat_g *PolyCNTT
	psi     *PolyCNTT
	phi     *PolyCNTT
	chseed  []byte
	cmt_zs  [][]*PolyCNTTVec
	zs      []*PolyCNTTVec
}

type CoinbaseTxv2 struct {
	Vin        uint64
	OutputTxos []*Txo
	TxWitness  *CbTxWitnessv2
}

type CbTxWitnessv2 struct {
	b_hat      *PolyCNTTVec
	c_hats     []*PolyCNTT
	u_p        []int64
	rpulpproof *rpulpProofv2
}

type TxInputDescv2 struct {
	txoList         []*LgrTxo // todo: refactor lgrTxoList
	sidx            int
	serializedASksp []byte
	serializedASksn []byte
	serializedVPk   []byte
	serializedVSk   []byte
	value           uint64
}

//func (pp *PublicParameter) SerializeTxInputDescv2(inputDesc *TxInputDescv2) []byte {
//
//	length := len(inputDesc.txoList)*(pp.SerializeSizeTxo()+len(inputDesc.txoList[0].Id)) + 4
//	bytes.NewBuffer(make([]byte, 0, length))
//	lengthOfAPk := len(inputDesc.serializedAPk)
//	lengthOfVPk := len(inputDesc.serializedVPk)
//	totalLength := 4 + 4 + lengthOfAPk + 4 + lengthOfVPk + 8
//	w := bytes.NewBuffer(make([]byte, 0, totalLength))
//	// total length
//	w.WriteByte(byte(int32(totalLength) >> 0))
//	w.WriteByte(byte(int32(totalLength) >> 8))
//	w.WriteByte(byte(int32(totalLength) >> 16))
//	w.WriteByte(byte(int32(totalLength) >> 24))
//	// length of apk
//	w.WriteByte(byte(int32(lengthOfAPk) >> 0))
//	w.WriteByte(byte(int32(lengthOfAPk) >> 8))
//	w.WriteByte(byte(int32(lengthOfAPk) >> 16))
//	w.WriteByte(byte(int32(lengthOfAPk) >> 24))
//	// apk
//	w.Write(inputDesc.serializedAPk)
//	//length of vpk
//	w.WriteByte(byte(int32(lengthOfVPk) >> 0))
//	w.WriteByte(byte(int32(lengthOfVPk) >> 8))
//	w.WriteByte(byte(int32(lengthOfVPk) >> 16))
//	w.WriteByte(byte(int32(lengthOfVPk) >> 24))
//	w.Write(inputDesc.serializedVPk)
//	// value
//	w.WriteByte(byte(inputDesc.value >> 0))
//	w.WriteByte(byte(inputDesc.value >> 8))
//	w.WriteByte(byte(inputDesc.value >> 16))
//	w.WriteByte(byte(inputDesc.value >> 24))
//	w.WriteByte(byte(inputDesc.value >> 32))
//	w.WriteByte(byte(inputDesc.value >> 40))
//	w.WriteByte(byte(inputDesc.value >> 48))
//	w.WriteByte(byte(inputDesc.value >> 56))
//	return w.Bytes()
//}

//func (pp *PublicParameter) DeserializeTxInputDescv2(b []byte) (*TxInputDescv2, error) {
//	var err error
//	var n int
//	r := bytes.NewReader(b)
//	// total length
//	lengthBytes := make([]byte, 4)
//	n, err = r.Read(lengthBytes)
//	if n != 4 || err != nil {
//		return nil, err
//	}
//	totalLength := int32(lengthBytes[0]) << 0
//	totalLength |= int32(lengthBytes[1]) << 8
//	totalLength |= int32(lengthBytes[2]) << 16
//	totalLength |= int32(lengthBytes[3]) << 24
//	// check the total length
//	if len(b) < int(totalLength) {
//		return nil, errors.New("the byte array with invalid length")
//	}
//
//	n, err = r.Read(lengthBytes)
//	if n != 4 || err != nil {
//		return nil, err
//	}
//	lengthOfAPk := int32(lengthBytes[0]) << 0
//	lengthOfAPk |= int32(lengthBytes[1]) << 8
//	lengthOfAPk |= int32(lengthBytes[2]) << 16
//	lengthOfAPk |= int32(lengthBytes[3]) << 24
//	serializedAPk := make([]byte, lengthOfAPk)
//	n, err = r.Read(serializedAPk)
//	if n != int(lengthOfAPk) || err != nil {
//		return nil, err
//	}
//
//	n, err = r.Read(lengthBytes)
//	if n != 4 || err != nil {
//		return nil, err
//	}
//	lengthOfVPk := int32(lengthBytes[0]) << 0
//	lengthOfVPk |= int32(lengthBytes[1]) << 8
//	lengthOfVPk |= int32(lengthBytes[2]) << 16
//	lengthOfVPk |= int32(lengthBytes[3]) << 24
//	serializedVPk := make([]byte, lengthOfVPk)
//	n, err = r.Read(serializedVPk)
//	if n != int(lengthOfVPk) || err != nil {
//		return nil, err
//	}
//
//	lengthBytes = make([]byte, 8)
//	n, err = r.Read(lengthBytes)
//	if n != 4 || err != nil {
//		return nil, err
//	}
//	value := uint64(lengthBytes[0]) << 0
//	value |= uint64(lengthBytes[1]) << 8
//	value |= uint64(lengthBytes[2]) << 16
//	value |= uint64(lengthBytes[3]) << 24
//	value |= uint64(lengthBytes[4]) << 32
//	value |= uint64(lengthBytes[5]) << 40
//	value |= uint64(lengthBytes[6]) << 48
//	value |= uint64(lengthBytes[7]) << 56
//
//	return &TxOutputDescv2{
//		serializedAPk: serializedAPk,
//		serializedVPk: serializedVPk,
//		value:         value,
//	}, nil
//}

func NewTxInputDescv2(txoList []*LgrTxo, sidx int, serializedASksp []byte, serializedASksn []byte, serializedVPk []byte, serializedVSk []byte, value uint64) *TxInputDescv2 {
	return &TxInputDescv2{
		txoList:         txoList,
		sidx:            sidx,
		serializedASksp: serializedASksp,
		serializedASksn: serializedASksn,
		serializedVPk:   serializedVPk,
		serializedVSk:   serializedVSk,
		value:           value,
	}
}

type TxOutputDescv2 struct {
	serializedAPk []byte
	serializedVPk []byte
	value         uint64
}

func (pp *PublicParameter) SerializeTxOutputDescv2(outputDesc *TxOutputDescv2) []byte {
	lengthOfAPk := len(outputDesc.serializedAPk)
	lengthOfVPk := len(outputDesc.serializedVPk)
	totalLength := 4 + 4 + lengthOfAPk + 4 + lengthOfVPk + 8
	w := bytes.NewBuffer(make([]byte, 0, totalLength))
	// total length
	w.WriteByte(byte(int32(totalLength) >> 0))
	w.WriteByte(byte(int32(totalLength) >> 8))
	w.WriteByte(byte(int32(totalLength) >> 16))
	w.WriteByte(byte(int32(totalLength) >> 24))
	// length of apk
	w.WriteByte(byte(int32(lengthOfAPk) >> 0))
	w.WriteByte(byte(int32(lengthOfAPk) >> 8))
	w.WriteByte(byte(int32(lengthOfAPk) >> 16))
	w.WriteByte(byte(int32(lengthOfAPk) >> 24))
	// apk
	w.Write(outputDesc.serializedAPk)
	//length of vpk
	w.WriteByte(byte(int32(lengthOfVPk) >> 0))
	w.WriteByte(byte(int32(lengthOfVPk) >> 8))
	w.WriteByte(byte(int32(lengthOfVPk) >> 16))
	w.WriteByte(byte(int32(lengthOfVPk) >> 24))
	w.Write(outputDesc.serializedVPk)
	// value
	w.WriteByte(byte(outputDesc.value >> 0))
	w.WriteByte(byte(outputDesc.value >> 8))
	w.WriteByte(byte(outputDesc.value >> 16))
	w.WriteByte(byte(outputDesc.value >> 24))
	w.WriteByte(byte(outputDesc.value >> 32))
	w.WriteByte(byte(outputDesc.value >> 40))
	w.WriteByte(byte(outputDesc.value >> 48))
	w.WriteByte(byte(outputDesc.value >> 56))
	return w.Bytes()
}

func (pp *PublicParameter) DeserializeTxOutputDescv2(b []byte) (*TxOutputDescv2, error) {
	var err error
	var n int
	r := bytes.NewReader(b)
	// total length
	lengthBytes := make([]byte, 4)
	n, err = r.Read(lengthBytes)
	if n != 4 || err != nil {
		return nil, err
	}
	totalLength := int32(lengthBytes[0]) << 0
	totalLength |= int32(lengthBytes[1]) << 8
	totalLength |= int32(lengthBytes[2]) << 16
	totalLength |= int32(lengthBytes[3]) << 24
	// check the total length
	if len(b) < int(totalLength) {
		return nil, errors.New("the byte array with invalid length")
	}

	n, err = r.Read(lengthBytes)
	if n != 4 || err != nil {
		return nil, err
	}
	lengthOfAPk := int32(lengthBytes[0]) << 0
	lengthOfAPk |= int32(lengthBytes[1]) << 8
	lengthOfAPk |= int32(lengthBytes[2]) << 16
	lengthOfAPk |= int32(lengthBytes[3]) << 24
	serializedAPk := make([]byte, lengthOfAPk)
	n, err = r.Read(serializedAPk)
	if n != int(lengthOfAPk) || err != nil {
		return nil, err
	}

	n, err = r.Read(lengthBytes)
	if n != 4 || err != nil {
		return nil, err
	}
	lengthOfVPk := int32(lengthBytes[0]) << 0
	lengthOfVPk |= int32(lengthBytes[1]) << 8
	lengthOfVPk |= int32(lengthBytes[2]) << 16
	lengthOfVPk |= int32(lengthBytes[3]) << 24
	serializedVPk := make([]byte, lengthOfVPk)
	n, err = r.Read(serializedVPk)
	if n != int(lengthOfVPk) || err != nil {
		return nil, err
	}

	lengthBytes = make([]byte, 8)
	n, err = r.Read(lengthBytes)
	if n != 4 || err != nil {
		return nil, err
	}
	value := uint64(lengthBytes[0]) << 0
	value |= uint64(lengthBytes[1]) << 8
	value |= uint64(lengthBytes[2]) << 16
	value |= uint64(lengthBytes[3]) << 24
	value |= uint64(lengthBytes[4]) << 32
	value |= uint64(lengthBytes[5]) << 40
	value |= uint64(lengthBytes[6]) << 48
	value |= uint64(lengthBytes[7]) << 56

	return &TxOutputDescv2{
		serializedAPk: serializedAPk,
		serializedVPk: serializedVPk,
		value:         value,
	}, nil
}

func NewTxOutputDescv2(serializedAPk []byte, serializedVPk []byte, value uint64) *TxOutputDescv2 {
	return &TxOutputDescv2{
		serializedAPk: serializedAPk,
		serializedVPk: serializedVPk,
		value:         value,
	}
}

type TransferTxv2 struct {
	//	Version uint32
	Inputs     []*TrTxInputv2
	OutputTxos []*Txo
	Fee        uint64

	TxMemo []byte

	TxWitness *TrTxWitnessv2
}

type TrTxInputv2 struct {
	TxoList      []*LgrTxo
	SerialNumber []byte
}

type TrTxWitnessv2 struct {
	ma_ps      []*PolyANTT
	cmt_ps     []*ValueCommitment
	elrsSigs   []*elrsSignaturev2
	b_hat      *PolyCNTTVec
	c_hats     []*PolyCNTT
	u_p        []int64
	rpulpproof *rpulpProofv2
}

type elrsSignaturev2 struct {
	seeds [][]byte
	z_as  []*PolyANTTVec
	z_cs  [][]*PolyCNTTVec
	z_cps [][]*PolyCNTTVec
}

func (pp *PublicParameter) AddressKeyGen(seed []byte) (apk *AddressPublicKey, ask *AddressSecretKey, err error) {
	var s *PolyANTTVec

	// check the validity of the length of seed
	if seed != nil && len(seed) != pp.paramSeedBytesLen {
		return nil, nil, errors.New("the length of seed is invalid")
	}
	if seed == nil {
		seed = RandomBytes(pp.paramSeedBytesLen)
	}

	// this temporary byte slice is for protect seed unmodified
	tmp := make([]byte, pp.paramSeedBytesLen)
	for i := 0; i < pp.paramSeedBytesLen; i++ {
		tmp[i] = seed[i]
	}
	ts, err := pp.expandRandomnessA(tmp)
	if err != nil {
		return nil, nil, err
	}
	s = pp.NTTPolyAVec(ts)

	tmp = make([]byte, pp.paramSeedBytesLen+2)
	for i := 0; i < pp.paramSeedBytesLen; i++ {
		tmp[i] = seed[i]
	}

	mat := rejectionUniformWithQa(append([]byte{'M', 'A'}, seed...), pp.paramDA, pp.paramQA)
	ma := &PolyANTT{coeffs: mat}

	// t = A * s, will be as a part of public key
	t := pp.PolyANTTMatrixMulVector(pp.paramMatrixA, s, pp.paramKA, pp.paramLA)

	// e = <a,s>+ma
	e := pp.PolyANTTAdd(pp.PolyANTTVecInnerProduct(pp.paramVecA, s, pp.paramLA), ma)

	apk = &AddressPublicKey{
		t: t,
		e: e,
	}
	ask = &AddressSecretKey{
		AddressSecretKeySp: &AddressSecretKeySp{s: s},
		AddressSecretKeySn: &AddressSecretKeySn{ma: ma},
	}
	return apk, ask, nil
}

func (pp *PublicParameter) ValueKeyGen(seed []byte) ([]byte, []byte, error) {
	return pqringctkem.KeyGen(pp.paramKem, seed, pp.paramSeedBytesLen)
}

// txoGen returns an transaction output and a random polynomial related to the corresponding transaction output with the master public key and value
func (pp *PublicParameter) txoGen(apk *AddressPublicKey, vpk []byte, vin uint64) (txo *Txo, cmtr *PolyCNTTVec, err error) {
	//	got (C, kappa) from key encapsulate mechanism
	// Restore the KEM version
	version := uint32(vpk[0]) << 0
	version |= uint32(vpk[1]) << 8
	version |= uint32(vpk[2]) << 16
	version |= uint32(vpk[3]) << 24
	if pqringctkem.VersionKEM(version) != pp.paramKem.Version {
		return nil, nil, errors.New("the version of kem is not matched")
	}
	CkemSerialzed, kappa, err := pqringctkem.Encaps(pp.paramKem, vpk[4:])
	//	expand the kappa to PolyCVec with length Lc
	rctmp, err := pp.expandRandomnessC(kappa)
	if err != nil {
		return nil, nil, err
	}
	cmtr = pp.NTTPolyCVec(rctmp)

	mtmp := intToBinary(vin, pp.paramDC)
	m := &PolyCNTT{coeffs: mtmp}
	// [b c]^T = C*r + [0 m]^T
	cmt := &ValueCommitment{}
	cmt.b = pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, cmtr, pp.paramKC, pp.paramLC)
	cmt.c = pp.PolyCNTTAdd(
		pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[0], cmtr, pp.paramLC),
		m,
	)

	//	vc = m ^ sk
	//	todo: the vc should have length only N, to prevent the unused D-N bits of leaking information
	sk, err := pp.expandRandomBitsV(kappa)
	if err != nil {
		return nil, nil, err
	}
	vct := make([]byte, pp.paramDC)
	for i := 0; i < pp.paramDC; i++ {
		vct[i] = sk[i] ^ byte(mtmp[i])
	}

	rettxo := &Txo{
		apk,
		cmt,
		vct,
		CkemSerialzed,
	}

	return rettxo, cmtr, nil
}
func (pp *PublicParameter) rpulpProve(message []byte, cmts []*ValueCommitment, cmt_rs []*PolyCNTTVec,
	n int, b_hat *PolyCNTTVec, r_hat *PolyCNTTVec, c_hats []*PolyCNTT, msg_hats [][]int64, n2 int,
	n1 int, rpulpType RpUlpType, binMatrixB [][]byte,
	I int, J int, m int, u_hats [][]int64) (rpulppi *rpulpProofv2, err error) {
	return rpulpProve(pp, message, cmts, cmt_rs, n, b_hat, r_hat, c_hats, msg_hats, n2, n1, rpulpType, binMatrixB, I, J, m, u_hats)
}

func rpulpProve(pp *PublicParameter, message []byte, cmts []*ValueCommitment, cmt_rs []*PolyCNTTVec, n int,
	b_hat *PolyCNTTVec, r_hat *PolyCNTTVec, c_hats []*PolyCNTT, msg_hats [][]int64, n2 int,
	n1 int, rpulpType RpUlpType, binMatrixB [][]byte,
	I int, J int, m int, u_hats [][]int64) (rpulppi *rpulpProofv2, err error) {
	// c_waves[i] = <h_i, r_i> + m_i
	c_waves := make([]*PolyCNTT, n)
	for i := 0; i < n; i++ {
		t := pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[i+1], cmt_rs[i], pp.paramLC)
		c_waves[i] = pp.PolyCNTTAdd(t, &PolyCNTT{coeffs: msg_hats[i]})
	}

rpUlpProveRestart:

	cmt_ys := make([][]*PolyCNTTVec, pp.paramK)
	ys := make([]*PolyCNTTVec, pp.paramK)
	cmt_ws := make([][]*PolyCNTTVec, pp.paramK)
	ws := make([]*PolyCNTTVec, pp.paramK)
	for t := 0; t < pp.paramK; t++ {
		cmt_ys[t] = make([]*PolyCNTTVec, n)
		cmt_ws[t] = make([]*PolyCNTTVec, n)
		for i := 0; i < n; i++ {
			// random some element in the {s_etaC}^Lc space
			maskCi, err := pp.sampleMaskCv2()
			if err != nil {
				return nil, err
			}
			cmt_ys[t][i] = pp.NTTPolyCVec(maskCi)
			cmt_ws[t][i] = pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, cmt_ys[t][i], pp.paramKC, pp.paramLC)
		}

		maskC, err := pp.sampleMaskCv2()
		if err != nil {
			return nil, err
		}
		ys[t] = pp.NTTPolyCVec(maskC)
		ws[t] = pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, ys[t], pp.paramKC, pp.paramLC)
	}

	tmpg := pp.sampleUniformPloyWithLowZeros()
	g := pp.NTTPolyC(tmpg)
	// c_hat(n2+1)
	c_hat_g := pp.PolyCNTTAdd(pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+5], r_hat, pp.paramLC), g)

	// splicing the data to be processed
	tmp := pp.collectBytesForRPULP1(message, n, n1, n2, binMatrixB, m, cmts, b_hat, c_hats, rpulpType, I, J, u_hats, c_waves, cmt_ws, ws, c_hat_g)
	seed_rand, err := Hash(tmp) // todo_DONE
	if err != nil {
		return nil, err
	}
	//fmt.Println("prove seed_rand=", seed_rand)
	alphas, betas, gammas, err := pp.expandUniformRandomnessInRqZqC(seed_rand, n1, m)
	if err != nil {
		return nil, err
	}
	//	\tilde{\delta}^(t)_i, \hat{\delta}^(t)_i,
	delta_waves := make([][]*PolyCNTT, pp.paramK)
	delta_hats := make([][]*PolyCNTT, pp.paramK)
	for t := 0; t < pp.paramK; t++ {
		delta_waves[t] = make([]*PolyCNTT, n)
		delta_hats[t] = make([]*PolyCNTT, n)
		for i := 0; i < n; i++ {
			delta_waves[t][i] = pp.PolyCNTTVecInnerProduct(pp.PolyCNTTVecSub(pp.paramMatrixH[i+1], pp.paramMatrixH[0], pp.paramLC), cmt_ys[t][i], pp.paramLC)
			delta_hats[t][i] = pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[i+1], pp.PolyCNTTVecSub(ys[t], cmt_ys[t][i], pp.paramLC), pp.paramLC)
		}
	}
	//	psi, psi'
	psi := pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+6], r_hat, pp.paramLC)
	psip := pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+6], ys[0], pp.paramLC)

	for t := 0; t < pp.paramK; t++ {
		tmp1 := pp.NewPolyCNTT()
		tmp2 := pp.NewPolyCNTT()
		// sum(0->n1-1)
		for i := 0; i < n1; i++ {
			// <h_i , y_t>
			tmp := pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[i+1], ys[t], pp.paramLC)

			tmp1 = pp.PolyCNTTAdd(
				tmp1,
				// alpha[i] * (2 * m_i - mu) <h_i , y_t>
				pp.PolyCNTTMul(
					alphas[i],
					// (2 * m_i - mu) <h_i , y_t>
					pp.PolyCNTTMul(
						// 2 * m_i - mu
						pp.PolyCNTTSub(
							//  m_i+m_i
							pp.PolyCNTTAdd(
								&PolyCNTT{coeffs: msg_hats[i]},
								&PolyCNTT{coeffs: msg_hats[i]},
							),
							&PolyCNTT{coeffs: pp.paramMu},
						),
						tmp,
					),
				),
			)
			tmp2 = pp.PolyCNTTAdd(
				tmp2,
				// alpha[i] * <h_i , y_t> * <h_i , y_t>
				pp.PolyCNTTMul(alphas[i],
					pp.PolyCNTTMul(tmp, tmp),
				),
			)
		}

		psi = pp.PolyCNTTSub(psi, pp.PolyCNTTMul(betas[t], pp.sigmaInvPolyCNTT(tmp1, t)))
		psip = pp.PolyCNTTAdd(psip, pp.PolyCNTTMul(betas[t], pp.sigmaInvPolyCNTT(tmp2, t)))
	}
	//fmt.Printf("Prove\n")
	//fmt.Printf("psip = %v\n", psip)
	//	p^(t)_j:
	p := pp.genUlpPolyCNTTs(rpulpType, binMatrixB, I, J, gammas)

	//	phi
	phi := pp.NewZeroPolyCNTT()

	var inprd, dcInv big.Int
	dcInv.SetInt64(pp.paramDCInv)

	for t := 0; t < pp.paramK; t++ {
		tmp1 := pp.NewZeroPolyCNTT()
		for tau := 0; tau < pp.paramK; tau++ {

			tmp := pp.NewZeroPolyCNTT()
			for j := 0; j < n2; j++ {
				tmp = pp.PolyCNTTAdd(tmp, pp.PolyCNTTMul(p[t][j], &PolyCNTT{coeffs: msg_hats[j]}))
			}

			constPoly := pp.NewZeroPolyC()
			//constPoly.coeffs[0] = reduceToQc(intMatrixInnerProductWithReduction(u_hats, gammas[t], m, pp.paramDC, pp.paramQC) * int64(pp.paramDCInv))
			inprd.SetInt64(intMatrixInnerProductWithReduction(u_hats, gammas[t], m, pp.paramDC, pp.paramQC))
			inprd.Mul(&inprd, &dcInv)
			constPoly.coeffs[0] = reduceBigInt(&inprd, pp.paramQC)

			tmp = pp.PolyCNTTSub(tmp, pp.NTTPolyC(constPoly))
			tmp1 = pp.PolyCNTTAdd(tmp1, pp.sigmaPowerPolyCNTT(tmp, tau))
		}

		xt := pp.NewZeroPolyC()
		xt.coeffs[t] = pp.paramKInv

		tmp1 = pp.PolyCNTTMul(pp.NTTPolyC(xt), tmp1)

		phi = pp.PolyCNTTAdd(phi, tmp1)
	}

	phi = pp.PolyCNTTAdd(phi, g)
	//phiinv := pp.NTTInv(phi)
	//fmt.Println(phiinv)
	//fmt.Printf("Prove\n")
	//fmt.Printf("phi = %v\n", phi)
	//	phi'^(\xi)
	phips := make([]*PolyCNTT, pp.paramK)
	for xi := 0; xi < pp.paramK; xi++ {
		phips[xi] = pp.NewZeroPolyCNTT()

		for t := 0; t < pp.paramK; t++ {

			tmp1 := pp.NewZeroPolyCNTT()
			for tau := 0; tau < pp.paramK; tau++ {

				tmp := pp.NewZeroPolyCNTTVec(pp.paramLC)

				for j := 0; j < n2; j++ {
					tmp = pp.PolyCNTTVecAdd(
						tmp,
						pp.PolyCNTTVecScaleMul(p[t][j], pp.paramMatrixH[j+1], pp.paramLC),
						pp.paramLC)
				}

				tmp1 = pp.PolyCNTTAdd(
					tmp1,
					pp.sigmaPowerPolyCNTT(
						pp.PolyCNTTVecInnerProduct(tmp, ys[(xi-tau+pp.paramK)%pp.paramK], pp.paramLC),
						tau),
				)
			}

			xt := pp.NewZeroPolyC()
			xt.coeffs[t] = pp.paramKInv

			tmp1 = pp.PolyCNTTMul(pp.NTTPolyC(xt), tmp1)

			phips[xi] = pp.PolyCNTTAdd(phips[xi], tmp1)
		}

		phips[xi] = pp.PolyCNTTAdd(
			phips[xi],
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+5], ys[xi], pp.paramLC))
	}
	//fmt.Println("phips = ")
	//for i := 0; i < pp.paramK; i++ {
	//	fmt.Printf("phips[%d] = %v \n", i, phips[i])
	//}
	//fmt.Println("Prove")
	//fmt.Printf("rpulppi.phi =\n")
	//for i := 0; i < len(delta_hats); i++ {
	//	fmt.Printf("delta_hats[%d] = %v\n", i, phips[i])
	//}
	//	seed_ch and ch
	t := pp.collectBytesForRPULP2(tmp, delta_waves, delta_hats, psi, psip, phi, phips)
	chseed, err := Hash(t)
	if err != nil {
		return nil, err
	}
	ctmp, err := pp.expandChallenge(chseed)
	if err != nil {
		return nil, err
	}
	ch := pp.NTTPolyC(ctmp)
	// z = y + sigma^t(c) * r
	cmt_zs := make([][]*PolyCNTTVec, pp.paramK)
	zs := make([]*PolyCNTTVec, pp.paramK)
	for t := 0; t < pp.paramK; t++ {
		cmt_zs[t] = make([]*PolyCNTTVec, n)
		sigma_t_ch := pp.sigmaPowerPolyCNTT(ch, t)
		for i := 0; i < n; i++ {
			cmt_zs[t][i] = pp.PolyCNTTVecAdd(
				cmt_ys[t][i],
				pp.PolyCNTTVecScaleMul(sigma_t_ch, cmt_rs[i], pp.paramLC),
				pp.paramLC)
			if pp.NTTInvPolyCVec(cmt_zs[t][i]).infNorm() > pp.paramEtaC-int64(pp.paramBetaC) {
				goto rpUlpProveRestart
			}
		}

		zs[t] = pp.PolyCNTTVecAdd(ys[t], pp.PolyCNTTVecScaleMul(sigma_t_ch, r_hat, pp.paramLC), pp.paramLC)

		if pp.NTTInvPolyCVec(zs[t]).infNorm() > pp.paramEtaC-int64(pp.paramBetaC) {
			goto rpUlpProveRestart
		}
	}

	retrpulppi := &rpulpProofv2{
		c_waves: c_waves,
		c_hat_g: c_hat_g,
		psi:     psi,
		phi:     phi,
		chseed:  chseed,
		cmt_zs:  cmt_zs,
		zs:      zs,
	}

	return retrpulppi, nil
}

func (pp PublicParameter) rpulpVerify(message []byte,
	cmts []*ValueCommitment, n int,
	b_hat *PolyCNTTVec, c_hats []*PolyCNTT, n2 int,
	n1 int, rpulpType RpUlpType, binMatrixB [][]byte, I int, J int, m int, u_hats [][]int64,
	rpulppi *rpulpProofv2) (valid bool) {

	if !(n >= 2 && n <= n1 && n1 <= n2 && n <= pp.paramI+pp.paramJ && n2 <= pp.paramI+pp.paramJ+4) {
		return false
	}

	if len(cmts) != n {
		return false
	}

	if b_hat == nil {
		return false
	}

	if len(c_hats) != n2 {
		return false
	}

	// check the matrix and u_hats
	if len(binMatrixB) != pp.paramDC {
		return false
	} else {
		for i := 0; i < len(binMatrixB); i++ {
			if len(binMatrixB[0]) != pp.paramDC/8 {
				//	todo: sometimes 2*pp.paramDC/8
				//return false
			}
		}
	}
	if len(u_hats) != m {
		return false
	} else {
		for i := 0; i < len(u_hats); i++ {
			if len(u_hats[0]) != pp.paramDC {
				return false
			}
		}

	}
	// check the well-formness of the \pi
	if len(rpulppi.c_waves) != n || len(rpulppi.c_hat_g.coeffs) != pp.paramDC || len(rpulppi.psi.coeffs) != pp.paramDC || len(rpulppi.phi.coeffs) != pp.paramDC || len(rpulppi.zs) != pp.paramK || len(rpulppi.zs[0].polyCNTTs) != pp.paramLC {
		return false
	}
	if rpulppi == nil {
		return false
	}
	if len(rpulppi.c_waves) != n {
		return false
	}

	if rpulppi.c_hat_g == nil || rpulppi.psi == nil || rpulppi.phi == nil || rpulppi.chseed == nil {
		return false
	}

	if rpulppi.cmt_zs == nil || len(rpulppi.cmt_zs) != pp.paramK || rpulppi.zs == nil || len(rpulppi.zs) != pp.paramK {
		return false
	}

	for t := 0; t < pp.paramK; t++ {
		if rpulppi.cmt_zs[t] == nil || len(rpulppi.cmt_zs[t]) != n {
			return false
		}
	}

	//	(phi_t[0] ... phi_t[k-1] = 0)
	phiPoly := pp.NTTInvPolyC(rpulppi.phi)
	//fmt.Println("phiPoly", phiPoly.coeffs1)
	for t := 0; t < pp.paramK; t++ {
		if phiPoly.coeffs[t] != 0 {
			// TODO 20210609 exist something theoretical error
			return false
		}
	}

	// infNorm of z^t_i and z^t
	for t := 0; t < pp.paramK; t++ {

		for i := 0; i < n; i++ {
			if pp.NTTInvPolyCVec(rpulppi.cmt_zs[t][i]).infNorm() > pp.paramEtaC-int64(pp.paramBetaC) {
				return false
			}
		}

		if pp.NTTInvPolyCVec(rpulppi.zs[t]).infNorm() > pp.paramEtaC-int64(pp.paramBetaC) {
			return false
		}

	}
	chmp, err := pp.expandChallenge(rpulppi.chseed)
	if err != nil {
		return false
	}
	ch := pp.NTTPolyC(chmp)

	sigma_chs := make([]*PolyCNTT, pp.paramK)
	//	w^t_i, w_t
	cmt_ws := make([][]*PolyCNTTVec, pp.paramK)
	ws := make([]*PolyCNTTVec, pp.paramK)
	for t := 0; t < pp.paramK; t++ {
		sigma_chs[t] = pp.sigmaPowerPolyCNTT(ch, t)

		cmt_ws[t] = make([]*PolyCNTTVec, n)
		for i := 0; i < n; i++ {
			cmt_ws[t][i] = pp.PolyCNTTVecSub(
				pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, rpulppi.cmt_zs[t][i], pp.paramKC, pp.paramLC),
				pp.PolyCNTTVecScaleMul(sigma_chs[t], cmts[i].b, pp.paramKC),
				pp.paramKC)
		}
		ws[t] = pp.PolyCNTTVecSub(
			pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, rpulppi.zs[t], pp.paramKC, pp.paramLC),
			pp.PolyCNTTVecScaleMul(sigma_chs[t], b_hat, pp.paramKC),
			pp.paramKC)
	}

	// splicing the data to be processed

	tmp := pp.collectBytesForRPULP1(message, n, n1, n2, binMatrixB, m, cmts, b_hat, c_hats, rpulpType, I, J, u_hats, rpulppi.c_waves, cmt_ws, ws, rpulppi.c_hat_g)
	seed_rand, err := Hash(tmp)
	if err != nil {
		return false
	}
	//fmt.Println("verify seed_rand=", seed_rand)
	alphas, betas, gammas, err := pp.expandUniformRandomnessInRqZqC(seed_rand, n1, m)
	if err != nil {
		return false
	}

	//	\tilde{\delta}^(t)_i, \hat{\delta}^(t)_i,
	delta_waves := make([][]*PolyCNTT, pp.paramK)
	delta_hats := make([][]*PolyCNTT, pp.paramK)
	for t := 0; t < pp.paramK; t++ {
		delta_waves[t] = make([]*PolyCNTT, n)
		delta_hats[t] = make([]*PolyCNTT, n)

		for i := 0; i < n; i++ {
			delta_waves[t][i] = pp.PolyCNTTSub(
				pp.PolyCNTTVecInnerProduct(
					pp.PolyCNTTVecSub(pp.paramMatrixH[i+1], pp.paramMatrixH[0], pp.paramLC),
					rpulppi.cmt_zs[t][i],
					pp.paramLC),
				pp.PolyCNTTMul(sigma_chs[t], pp.PolyCNTTSub(rpulppi.c_waves[i], cmts[i].c)),
			)

			delta_hats[t][i] = pp.PolyCNTTSub(
				pp.PolyCNTTVecInnerProduct(
					pp.paramMatrixH[i+1],
					pp.PolyCNTTVecSub(rpulppi.zs[t], rpulppi.cmt_zs[t][i], pp.paramLC),
					pp.paramLC),
				pp.PolyCNTTMul(sigma_chs[t], pp.PolyCNTTSub(c_hats[i], rpulppi.c_waves[i])),
			)
		}
	}
	// psi'
	psip := pp.NewZeroPolyCNTT()
	mu := &PolyCNTT{coeffs: pp.paramMu}
	for t := 0; t < pp.paramK; t++ {

		tmp1 := pp.NewZeroPolyCNTT()
		tmp2 := pp.NewZeroPolyCNTT()

		for i := 0; i < n1; i++ {
			f_t_i := pp.PolyCNTTSub(
				//<h_i,z_t>
				pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[i+1], rpulppi.zs[t], pp.paramLC),
				// sigma_c_t
				pp.PolyCNTTMul(sigma_chs[t], c_hats[i]),
			)

			tmp := pp.PolyCNTTMul(alphas[i], f_t_i)

			tmp1 = pp.PolyCNTTAdd(
				tmp1,
				pp.PolyCNTTMul(tmp, f_t_i),
			)

			tmp2 = pp.PolyCNTTAdd(
				tmp2,
				tmp,
			)
		}
		tmp2 = pp.PolyCNTTMul(tmp2, mu)
		tmp2 = pp.PolyCNTTMul(tmp2, sigma_chs[t])

		tmp1 = pp.PolyCNTTAdd(tmp1, tmp2)
		tmp1 = pp.sigmaInvPolyCNTT(tmp1, t)
		tmp1 = pp.PolyCNTTMul(betas[t], tmp1)

		psip = pp.PolyCNTTAdd(psip, tmp1)
	}

	psip = pp.PolyCNTTSub(psip, pp.PolyCNTTMul(ch, rpulppi.psi))
	psip = pp.PolyCNTTAdd(psip,
		pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+6], rpulppi.zs[0], pp.paramLC))
	//fmt.Printf("Verify\n")
	//fmt.Printf("psip = %v\n", psip)
	//	p^(t)_j:
	p := pp.genUlpPolyCNTTs(rpulpType, binMatrixB, I, J, gammas)

	//	phip
	phip := pp.NewZeroPolyCNTT()
	var inprd, dcInv big.Int
	dcInv.SetInt64(pp.paramDCInv)

	for t := 0; t < pp.paramK; t++ {
		tmp1 := pp.NewZeroPolyCNTT()
		for tau := 0; tau < pp.paramK; tau++ {

			tmp := pp.NewZeroPolyCNTT()
			for j := 0; j < n2; j++ {
				tmp = pp.PolyCNTTAdd(tmp, pp.PolyCNTTMul(p[t][j], c_hats[j]))
			}

			constPoly := pp.NewZeroPolyC()
			inprd.SetInt64(intMatrixInnerProductWithReduction(u_hats, gammas[t], m, pp.paramDC, pp.paramQC))
			inprd.Mul(&inprd, &dcInv)
			constPoly.coeffs[0] = reduceBigInt(&inprd, pp.paramQC)

			tmp = pp.PolyCNTTSub(tmp, pp.NTTPolyC(constPoly))

			tmp1 = pp.PolyCNTTAdd(tmp1, pp.sigmaPowerPolyCNTT(tmp, tau))
		}

		xt := pp.NewZeroPolyC()
		xt.coeffs[t] = pp.paramKInv

		tmp1 = pp.PolyCNTTMul(pp.NTTPolyC(xt), tmp1)

		phip = pp.PolyCNTTAdd(phip, tmp1)
	}

	//	phi'^(\xi)
	phips := make([]*PolyCNTT, pp.paramK)
	constterm := pp.PolyCNTTSub(pp.PolyCNTTAdd(phip, rpulppi.c_hat_g), rpulppi.phi)

	for xi := 0; xi < pp.paramK; xi++ {
		phips[xi] = pp.NewZeroPolyCNTT()

		for t := 0; t < pp.paramK; t++ {

			tmp1 := pp.NewZeroPolyCNTT()
			for tau := 0; tau < pp.paramK; tau++ {

				tmp := pp.NewZeroPolyCNTTVec(pp.paramLC)

				for j := 0; j < n2; j++ {
					tmp = pp.PolyCNTTVecAdd(
						tmp,
						pp.PolyCNTTVecScaleMul(p[t][j], pp.paramMatrixH[j+1], pp.paramLC),
						pp.paramLC)
				}

				tmp1 = pp.PolyCNTTAdd(
					tmp1,
					pp.sigmaPowerPolyCNTT(
						pp.PolyCNTTVecInnerProduct(tmp, rpulppi.zs[(xi-tau+pp.paramK)%pp.paramK], pp.paramLC),
						tau),
				)
			}

			xt := pp.NewZeroPolyC()
			xt.coeffs[t] = pp.paramKInv

			tmp1 = pp.PolyCNTTMul(pp.NTTPolyC(xt), tmp1)

			phips[xi] = pp.PolyCNTTAdd(phips[xi], tmp1)
		}

		phips[xi] = pp.PolyCNTTAdd(
			phips[xi],
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+5], rpulppi.zs[xi], pp.paramLC))

		phips[xi] = pp.PolyCNTTSub(
			phips[xi],
			pp.PolyCNTTMul(sigma_chs[xi], constterm))
	}
	//fmt.Printf("Verify\n")
	//
	//fmt.Printf("phips = \n")
	//for i := 0; i < pp.paramK; i++ {
	//	fmt.Printf("phips[%d] = %v \n", i, phips[i])
	//}
	//fmt.Println("Verify")
	//fmt.Printf("rpulppi.phi =\n")
	//for i := 0; i < len(delta_hats); i++ {
	//	for j := 0; j < len(delta_hats[i]); j++ {
	//		fmt.Printf("delta_hats[%d][%d] = %v\n", i, j, delta_hats[i][j])
	//	}
	//}
	//	seed_ch and ch
	t := pp.collectBytesForRPULP2(tmp, delta_waves, delta_hats, rpulppi.psi, psip, rpulppi.phi, phips)
	seed_ch, err := Hash(t)
	if err != nil {
		return false
	}
	if bytes.Compare(seed_ch, rpulppi.chseed) != 0 {
		return false
	}

	return true
}

//	todo_DONE: this method directly samples and returns a PloyANTT
func (pp *PublicParameter) ExpandKIDR(lgrtxo *LgrTxo) *PolyANTT {
	buf := make([]byte, 0, 1000)
	w := bytes.NewBuffer(buf)
	var err error
	serialize, err := pp.LgrTxoSerialize(lgrtxo)
	if err != nil {
		log.Fatalln("error for pp.LgrTxoSerialize()")
		return nil
	}
	_, err = w.Write(serialize)
	if err != nil {
		log.Fatalln("error for w.Write()")
		return nil
	}
	seed, err := Hash(w.Bytes())
	if err != nil {
		return nil
	}
	got := rejectionUniformWithQa(seed, pp.paramDA, pp.paramQA)
	return &PolyANTT{coeffs: got}
}

//	todo_DONE: (ringHash, index) shall be ok?

func (pp *PublicParameter) ELRSSign(
	lgrTxoList []*LgrTxo, ma_p *PolyANTT, cmt_p *ValueCommitment,
	msg []byte, sindex int, sa *PolyANTTVec, rc *PolyCNTTVec, rc_p *PolyCNTTVec) (*elrsSignaturev2, error) {
	var err error
	ringLen := len(lgrTxoList)
	if ringLen == 0 {
		return nil, errors.New("ELRSSign is called on input empty ring")
	}
	if sindex >= ringLen {
		return nil, errors.New("The signer index is not in the scope")
	}

	seeds := make([][]byte, ringLen)
	z_as := make([]*PolyANTTVec, ringLen)

	w_as := make([]*PolyANTTVec, ringLen)
	delta_as := make([]*PolyANTT, ringLen)

	z_cs := make([][]*PolyCNTTVec, ringLen)
	z_cps := make([][]*PolyCNTTVec, ringLen)

	w_cs := make([][]*PolyCNTTVec, ringLen)
	w_cps := make([][]*PolyCNTTVec, ringLen)
	delta_cs := make([][]*PolyCNTT, ringLen)

	for j := 0; j < ringLen; j++ {
		if j == sindex {
			continue
		}
		seeds[j] = RandomBytes(pp.paramSeedBytesLen)

		tmpA, err := pp.expandChallengeA(seeds[j])
		if err != nil {
			return nil, err
		}
		da := pp.NTTPolyA(tmpA)

		tmpC, err := pp.expandChallengeC(seeds[j])
		if err != nil {
			return nil, err
		}
		dc := pp.NTTPolyC(tmpC)

		// sample randomness for z_a_j
		tmpZa, err := pp.sampleZetaA()
		if err != nil {
			return nil, err
		}
		z_as[j] = pp.NTTPolyAVec(tmpZa)

		// w_a_j = A*z_a_j - d_a_j*t_j
		w_as[j] = pp.PolyANTTVecSub(
			pp.PolyANTTMatrixMulVector(pp.paramMatrixA, z_as[j], pp.paramKA, pp.paramLA),
			pp.PolyANTTVecScaleMul(da, lgrTxoList[j].Txo.AddressPublicKey.t, pp.paramKA),
			pp.paramKA,
		)
		// theta_a_j = <a,z_a_j> - d_a_j * (e_j + ExpandKIDR(txo[j]) - m_a_p)
		delta_as[j] = pp.PolyANTTSub(
			pp.PolyANTTVecInnerProduct(pp.paramVecA, z_as[j], pp.paramLA),
			pp.PolyANTTMul(
				da,
				pp.PolyANTTSub(
					pp.PolyANTTAdd(
						lgrTxoList[j].Txo.AddressPublicKey.e,
						pp.ExpandKIDR(lgrTxoList[j]),
					),
					ma_p,
				),
			),
		)

		z_cs[j] = make([]*PolyCNTTVec, pp.paramK)
		z_cps[j] = make([]*PolyCNTTVec, pp.paramK)

		w_cs[j] = make([]*PolyCNTTVec, pp.paramK)
		w_cps[j] = make([]*PolyCNTTVec, pp.paramK)

		delta_cs[j] = make([]*PolyCNTT, pp.paramK)
		for tao := 0; tao < pp.paramK; tao++ {
			tmpZc, err := pp.sampleZetaC2v2()
			if err != nil {
				return nil, err
			}
			tmpZcp, err := pp.sampleZetaC2v2()
			if err != nil {
				return nil, err
			}
			z_cs[j][tao] = pp.NTTPolyCVec(tmpZc)
			z_cps[j][tao] = pp.NTTPolyCVec(tmpZcp)
			sigmatao := pp.sigmaPowerPolyCNTT(dc, tao)
			w_cs[j][tao] = pp.PolyCNTTVecSub(
				pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, z_cs[j][tao], pp.paramKC, pp.paramLC),
				pp.PolyCNTTVecScaleMul(
					sigmatao,
					lgrTxoList[j].Txo.ValueCommitment.b,
					pp.paramKC,
				),
				pp.paramKC,
			)
			w_cps[j][tao] = pp.PolyCNTTVecSub(
				pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, z_cps[j][tao], pp.paramKC, pp.paramLC),
				pp.PolyCNTTVecScaleMul(
					sigmatao,
					cmt_p.b,
					pp.paramKC,
				),
				pp.paramKC,
			)
			delta_cs[j][tao] = pp.PolyCNTTSub(
				pp.PolyCNTTVecInnerProduct(
					pp.paramMatrixH[0],
					pp.PolyCNTTVecSub(z_cs[j][tao], z_cps[j][tao], pp.paramLC),
					pp.paramLC,
				),
				pp.PolyCNTTMul(
					sigmatao,
					pp.PolyCNTTSub(lgrTxoList[j].Txo.ValueCommitment.c, cmt_p.c),
				),
			)
		}
	}

	z_cs[sindex] = make([]*PolyCNTTVec, pp.paramK)
	z_cps[sindex] = make([]*PolyCNTTVec, pp.paramK)
	delta_cs[sindex] = make([]*PolyCNTT, pp.paramK)
ELRSSignRestartv2:
	// randomness y_a_j_bar
	tmpYa, err := pp.sampleMaskA()
	if err != nil {
		return nil, err
	}
	y_a := pp.NTTPolyAVec(tmpYa)
	w_as[sindex] = pp.PolyANTTMatrixMulVector(pp.paramMatrixA, y_a, pp.paramKA, pp.paramLA)
	delta_as[sindex] = pp.PolyANTTVecInnerProduct(pp.paramVecA, y_a, pp.paramLA)

	y_cs := make([]*PolyCNTTVec, pp.paramK)
	y_cps := make([]*PolyCNTTVec, pp.paramK)

	w_cs[sindex] = make([]*PolyCNTTVec, pp.paramK)
	w_cps[sindex] = make([]*PolyCNTTVec, pp.paramK)
	for tao := 0; tao < pp.paramK; tao++ {
		tmpYc, err := pp.sampleMaskCv2()
		if err != nil {
			return nil, err
		}
		tmpYcp, err := pp.sampleMaskCv2()
		if err != nil {
			return nil, err
		}

		y_cs[tao] = pp.NTTPolyCVec(tmpYc)
		y_cps[tao] = pp.NTTPolyCVec(tmpYcp)
		w_cs[sindex][tao] = pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, y_cs[tao], pp.paramKC, pp.paramLC)
		w_cps[sindex][tao] = pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, y_cps[tao], pp.paramKC, pp.paramLC)
		delta_cs[sindex][tao] = pp.PolyCNTTVecInnerProduct(
			pp.paramMatrixH[0],
			pp.PolyCNTTVecSub(y_cs[tao], y_cps[tao], pp.paramLC),
			pp.paramLC,
		)
	}

	seed_ch, err := Hash(pp.collectBytesForELRv2(lgrTxoList, ma_p, cmt_p, msg, w_as, delta_as, w_cs, w_cps, delta_cs))
	if err != nil {
		return nil, err
	}
	/*	seeds[sindex] = make([]byte, len(seed_ch))
		for i := 0; i < len(seed_ch); i++ {
			seeds[sindex][i] = seed_ch[i]
		}*/
	seeds[sindex] = seed_ch
	seedByteLen := len(seed_ch)
	for j := 0; j < ringLen; j++ {
		if j == sindex {
			continue
		}
		for i := 0; i < seedByteLen; i++ {
			seeds[sindex][i] ^= seeds[j][i]
		}
	}

	tmpA, err := pp.expandChallengeA(seeds[sindex])
	if err != nil {
		return nil, err
	}
	tmpC, err := pp.expandChallengeC(seeds[sindex])
	if err != nil {
		return nil, err
	}
	dA := pp.NTTPolyA(tmpA)
	dC := pp.NTTPolyC(tmpC)

	z_as[sindex] = pp.PolyANTTVecAdd(y_a, pp.PolyANTTVecScaleMul(dA, sa, pp.paramLA), pp.paramLA)
	z_cs[sindex] = make([]*PolyCNTTVec, pp.paramK)
	z_cps[sindex] = make([]*PolyCNTTVec, pp.paramK)
	for tao := 0; tao < pp.paramK; tao++ {
		sigmaTao := pp.sigmaPowerPolyCNTT(dC, tao)
		z_cs[sindex][tao] = pp.PolyCNTTVecAdd(
			y_cs[tao],
			pp.PolyCNTTVecScaleMul(sigmaTao, rc, pp.paramLC),
			pp.paramLC,
		)
		z_cps[sindex][tao] = pp.PolyCNTTVecAdd(
			y_cps[tao],
			pp.PolyCNTTVecScaleMul(sigmaTao, rc_p, pp.paramLC),
			pp.paramLC,
		)
	}

	// todo: here we assume pp.paramThetaA*pp.paramGammaA is small
	if pp.NTTInvPolyAVec(z_as[sindex]).infNorm() > pp.paramEtaA-int64(pp.paramBetaA) {
		goto ELRSSignRestartv2
	}
	for tao := 0; tao < pp.paramK; tao++ {
		bound := pp.paramEtaC - int64(pp.paramBetaC)
		if pp.NTTInvPolyCVec(z_cs[sindex][tao]).infNorm() > bound {
			goto ELRSSignRestartv2
		}
		if pp.NTTInvPolyCVec(z_cps[sindex][tao]).infNorm() > bound {
			goto ELRSSignRestartv2
		}
	}
	return &elrsSignaturev2{
		seeds: seeds,
		z_as:  z_as,
		z_cs:  z_cs,
		z_cps: z_cps,
	}, nil
}

// todo_DONE: the paper is not accurate, use the following params
func (pp *PublicParameter) collectBytesForELRv2(
	lgxTxoList []*LgrTxo, ma_p *PolyANTT, cmt_p *ValueCommitment, msg []byte,
	w_as []*PolyANTTVec, delta_as []*PolyANTT,
	w_cs [][]*PolyCNTTVec, w_cps [][]*PolyCNTTVec, delta_cs [][]*PolyCNTT) []byte {
	tt := make([]byte, 0, len(msg)+pp.paramDC*4*
		(len(lgxTxoList)*(pp.paramKA+1+pp.paramKC+1+pp.paramKA+1+pp.paramK*pp.paramKC*2)+
			1+pp.paramKC+1))
	w := bytes.NewBuffer(tt)
	appendPolyANTTToBytes := func(a *PolyANTT) {
		for k := 0; k < pp.paramDA; k++ {
			w.WriteByte(byte(a.coeffs[k] >> 0))
			w.WriteByte(byte(a.coeffs[k] >> 8))
			w.WriteByte(byte(a.coeffs[k] >> 16))
			w.WriteByte(byte(a.coeffs[k] >> 24))
			w.WriteByte(byte(a.coeffs[k] >> 32))
			w.WriteByte(byte(a.coeffs[k] >> 40))
			w.WriteByte(byte(a.coeffs[k] >> 48))
			w.WriteByte(byte(a.coeffs[k] >> 56))

		}
	}
	appendPolyCNTTToBytes := func(a *PolyCNTT) {
		for k := 0; k < pp.paramDC; k++ {
			w.WriteByte(byte(a.coeffs[k] >> 0))
			w.WriteByte(byte(a.coeffs[k] >> 8))
			w.WriteByte(byte(a.coeffs[k] >> 16))
			w.WriteByte(byte(a.coeffs[k] >> 24))
			w.WriteByte(byte(a.coeffs[k] >> 32))
			w.WriteByte(byte(a.coeffs[k] >> 40))
			w.WriteByte(byte(a.coeffs[k] >> 48))
			w.WriteByte(byte(a.coeffs[k] >> 56))
		}
	}
	// msg
	w.Write(msg)
	// txoList=[(pk,cmt)]
	for i := 0; i < len(lgxTxoList); i++ {
		serialize, err := pp.LgrTxoSerialize(lgxTxoList[i])
		if err != nil {
			log.Fatalln("error for pp.LgrTxoSerialize()")
			return nil
		}
		_, err = w.Write(serialize)
		if err != nil {
			log.Fatalln("error for w.Write()")
			return nil
		}
	}
	// ma
	appendPolyANTTToBytes(ma_p)
	// cmt
	for i := 0; i < len(cmt_p.b.polyCNTTs); i++ {
		appendPolyCNTTToBytes(cmt_p.b.polyCNTTs[i])
	}
	appendPolyCNTTToBytes(cmt_p.c)
	// w_a_js
	for i := 0; i < len(w_as); i++ {
		for j := 0; j < len(w_as[i].polyANTTs); j++ {
			appendPolyANTTToBytes(w_as[i].polyANTTs[j])
		}
	}
	// delta_a_js
	for i := 0; i < len(delta_as); i++ {
		appendPolyANTTToBytes(delta_as[i])
	}

	// w_c_j_ts
	for i := 0; i < len(w_cs); i++ {
		for j := 0; j < len(w_cs[i]); j++ {
			for k := 0; k < len(w_cs[i][j].polyCNTTs); k++ {
				appendPolyCNTTToBytes(w_cs[i][j].polyCNTTs[k])
			}
		}
	}
	// w_c_j_tps
	for i := 0; i < len(w_cps); i++ {
		for j := 0; j < len(w_cps[i]); j++ {
			for k := 0; k < len(w_cps[i][j].polyCNTTs); k++ {
				appendPolyCNTTToBytes(w_cps[i][j].polyCNTTs[k])
			}
		}
	}
	// delta_cs [][]*PolyCNTT
	for i := 0; i < len(delta_cs); i++ {
		for j := 0; j < len(delta_cs[i]); j++ {
			appendPolyCNTTToBytes(delta_cs[i][j])
		}
	}
	sha := sha256.New()
	sha.Reset()
	res := sha.Sum(w.Bytes())
	return res[:]
}

func (pp *PublicParameter) ELRSVerify(lgrTxoList []*LgrTxo, ma_p *PolyANTT, cmt_p *ValueCommitment, msg []byte, sig *elrsSignaturev2) bool {
	ringLen := len(lgrTxoList)
	if ringLen == 0 {
		return false
	}
	boundA := pp.paramEtaA - int64(pp.paramBetaA)
	boundC := pp.paramEtaC - int64(pp.paramBetaC)
	for j := 0; j < ringLen; j++ {
		if pp.NTTInvPolyAVec(sig.z_as[j]).infNorm() > boundA {
			return false
		}
		for tao := 0; tao < pp.paramK; tao++ {
			if pp.NTTInvPolyCVec(sig.z_cs[j][tao]).infNorm() > boundC {
				return false
			}
			if pp.NTTInvPolyCVec(sig.z_cps[j][tao]).infNorm() > boundC {
				return false
			}
		}
	}

	w_as := make([]*PolyANTTVec, ringLen)
	delta_as := make([]*PolyANTT, ringLen)

	w_cs := make([][]*PolyCNTTVec, ringLen)
	w_cps := make([][]*PolyCNTTVec, ringLen)
	delta_cs := make([][]*PolyCNTT, ringLen)
	for j := 0; j < ringLen; j++ {
		tmpDA, err := pp.expandChallengeA(sig.seeds[j])
		if err != nil {
			return false
		}
		da := pp.NTTPolyA(tmpDA)

		tmpDC, err := pp.expandChallengeC(sig.seeds[j])
		if err != nil {
			return false
		}
		dc := pp.NTTPolyC(tmpDC)

		// w_a_j = A*z_a_j - d_a_j*t_j
		w_as[j] = pp.PolyANTTVecSub(
			pp.PolyANTTMatrixMulVector(pp.paramMatrixA, sig.z_as[j], pp.paramKA, pp.paramLA),
			pp.PolyANTTVecScaleMul(da, lgrTxoList[j].Txo.AddressPublicKey.t, pp.paramKA),
			pp.paramKA,
		)
		// theta_a_j = <a,z_a_j> - d_a_j * (e_j + ExpandKIDR(txo[j]) - m_a_p)
		delta_as[j] = pp.PolyANTTSub(
			pp.PolyANTTVecInnerProduct(pp.paramVecA, sig.z_as[j], pp.paramLA),
			pp.PolyANTTMul(
				da,
				pp.PolyANTTSub(
					pp.PolyANTTAdd(
						lgrTxoList[j].Txo.AddressPublicKey.e,
						pp.ExpandKIDR(lgrTxoList[j]),
					),
					ma_p,
				),
			),
		)

		w_cs[j] = make([]*PolyCNTTVec, pp.paramK)
		w_cps[j] = make([]*PolyCNTTVec, pp.paramK)
		delta_cs[j] = make([]*PolyCNTT, pp.paramK)
		for tao := 0; tao < pp.paramK; tao++ {
			sigmatao := pp.sigmaPowerPolyCNTT(dc, tao)
			w_cs[j][tao] = pp.PolyCNTTVecSub(
				pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, sig.z_cs[j][tao], pp.paramKC, pp.paramLC),
				pp.PolyCNTTVecScaleMul(
					sigmatao,
					lgrTxoList[j].Txo.ValueCommitment.b,
					pp.paramKC,
				),
				pp.paramKC,
			)
			w_cps[j][tao] = pp.PolyCNTTVecSub(
				pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, sig.z_cps[j][tao], pp.paramKC, pp.paramLC),
				pp.PolyCNTTVecScaleMul(
					sigmatao,
					cmt_p.b,
					pp.paramKC,
				),
				pp.paramKC,
			)
			delta_cs[j][tao] = pp.PolyCNTTSub(
				pp.PolyCNTTVecInnerProduct(
					pp.paramMatrixH[0],
					pp.PolyCNTTVecSub(sig.z_cs[j][tao], sig.z_cps[j][tao], pp.paramLC),
					pp.paramLC,
				),
				pp.PolyCNTTMul(
					sigmatao,
					pp.PolyCNTTSub(lgrTxoList[j].Txo.ValueCommitment.c, cmt_p.c),
				),
			)
		}
	}

	seed_ch, err := Hash(pp.collectBytesForELRv2(lgrTxoList, ma_p, cmt_p, msg, w_as, delta_as, w_cs, w_cps, delta_cs))
	if err != nil {
		return false
	}
	seedByteLen := len(seed_ch)
	for j := 0; j < ringLen; j++ {
		for i := 0; i < len(seed_ch); i++ {
			seed_ch[i] ^= sig.seeds[j][i]
		}
	}
	for i := 0; i < seedByteLen; i++ {
		if seed_ch[i] != 0 {
			return false
		}
	}
	return true
}

func (pp *PublicParameter) CoinbaseTxGen(vin uint64, txOutputDescs []*TxOutputDescv2) (cbTx *CoinbaseTxv2, err error) {
	V := uint64(1)<<pp.paramN - 1

	if vin >= V {
		return nil, errors.New("vin is not in [0, V]") // todo: more accurate info
	}

	if len(txOutputDescs) == 0 || len(txOutputDescs) > pp.paramJ {
		return nil, errors.New("the number of outputs is not in [1, I_max]") // todo: more accurate info
	}

	J := len(txOutputDescs)

	retcbTx := &CoinbaseTxv2{}
	//	retcbTx.Version = 0 // todo: how to set and how to use the version? The bpf just care the content of cbTx?
	retcbTx.Vin = vin
	retcbTx.OutputTxos = make([]*Txo, J)

	cmts := make([]*ValueCommitment, J)
	cmt_rs := make([]*PolyCNTTVec, J)

	vout := uint64(0)
	// generate the output using txoGen
	for j, txOutputDesc := range txOutputDescs {
		if txOutputDesc.value > V {
			return nil, errors.New("value is not in [0, V]") // todo: more accurate info, including the i
		}
		vout += txOutputDesc.value
		if vout > V {
			return nil, errors.New("the output value is not in [0, V]") // todo: more accurate info, including the i
		}

		// restore the apk from serializedAPk
		apk, err := pp.AddressPublicKeyDeserialize(txOutputDesc.serializedAPk)
		if err != nil {
			return nil, err
		}
		txo, cmtr, err := pp.txoGen(apk, txOutputDesc.serializedVPk, txOutputDesc.value)
		if err != nil {
			return nil, err
		}
		cmt_rs[j] = cmtr
		cmts[j] = txo.ValueCommitment
		retcbTx.OutputTxos[j] = txo
	}
	if vout > vin {
		return nil, errors.New("the output value exceeds the input value") // todo: more accurate info
	}

	cbTxCon := make([]byte, 0, 8)
	tw := bytes.NewBuffer(cbTxCon)
	tw.WriteByte(byte(vin >> 0))
	tw.WriteByte(byte(vin >> 8))
	tw.WriteByte(byte(vin >> 16))
	tw.WriteByte(byte(vin >> 24))
	tw.WriteByte(byte(vin >> 32))
	tw.WriteByte(byte(vin >> 40))
	tw.WriteByte(byte(vin >> 48))
	tw.WriteByte(byte(vin >> 56))
	for i := 0; i < J; i++ {
		serializedTxo, err := pp.TxoSerialize(retcbTx.OutputTxos[i])
		if err != nil {
			return nil, err
		}
		_, err = tw.Write(serializedTxo)
		if err != nil {
			return nil, errors.New("error in serializing txo")
		}
	}
	if J == 1 {
		// random from S_etaC^lc
		ys := make([]*PolyCNTTVec, pp.paramK)
		// w^t = B * y^t
		ws := make([]*PolyCNTTVec, pp.paramK)
		// delta = <h,y^t>
		deltas := make([]*PolyCNTT, pp.paramK)
		// z^t = y^t + sigma^t(c) * r_(out,j), r_(out,j) is from txoGen, in there, r_(out,j) is cmt_rs_j
		zs := make([]*PolyCNTTVec, pp.paramK)

	cbTxGenJ1Restart:
		for t := 0; t < pp.paramK; t++ {
			// random y
			maskC, err := pp.sampleMaskCv2()
			if err != nil {
				return nil, err
			}
			ys[t] = pp.NTTPolyCVec(maskC)

			ws[t] = pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, ys[t], pp.paramKC, pp.paramLC)
			deltas[t] = pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[0], ys[t], pp.paramLC)
		}

		chseed, err := Hash(pp.collectBytesForCoinbase1(cbTxCon, ws, deltas))
		if err != nil {
			return nil, err
		}

		chtmp, err := pp.expandChallengeC(chseed)
		if err != nil {
			return nil, err
		}
		ch := pp.NTTPolyC(chtmp)
		for t := 0; t < pp.paramK; t++ {
			zs[t] = pp.PolyCNTTVecAdd(
				ys[t],
				pp.PolyCNTTVecScaleMul(
					pp.sigmaPowerPolyCNTT(ch, t),
					cmt_rs[0],
					pp.paramLC,
				),
				pp.paramLC,
			)
			// check the norm
			if pp.NTTInvPolyCVec(zs[t]).infNorm() > pp.paramEtaC-int64(pp.paramBetaC) {
				goto cbTxGenJ1Restart
			}
		}

		retcbTx.TxWitness = &CbTxWitnessv2{
			rpulpproof: &rpulpProofv2{
				chseed: chseed,
				zs:     zs,
			},
		}
	} else {
		//	J >= 2
		n := J
		n2 := n + 2

		c_hats := make([]*PolyCNTT, n2)

		msg_hats := make([][]int64, n2)

		u_hats := make([][]int64, 3)
		u_hats[0] = intToBinary(vin, pp.paramDC)

		for j := 0; j < J; j++ {
			msg_hats[j] = intToBinary(txOutputDescs[j].value, pp.paramDC)
		}

		u := intToBinary(vin, pp.paramDC)

		//	f is the carry vector, such that, u = m_0 + m_1 + ... + m_{J-1}
		//	f[0] = 0, and for i=1 to d-1,
		//	m_0[i-1]+ ... + m_{J-1}[i-1] + f[i-1] = u[i-1] + 2 f[i],
		//	m_0[i-1]+ ... + m_{J-1}[i-1] + f[i-1] = u[i-1]
		f := make([]int64, pp.paramDC)
		f[0] = 0
		for i := 1; i < pp.paramDC; i++ {
			tmp := int64(0)
			for j := 0; j < J; j++ {
				tmp = tmp + msg_hats[j][i-1]
			}
			//f[i] = (tmp + f[i-1] - u[i-1]) >> 1
			f[i] = (tmp + f[i-1] - u[i-1]) / 2
		}
		msg_hats[J] = f

	cbTxGenJ2Restart:
		e := make([]int64, pp.paramDC)
		e, err := pp.sampleUniformWithinEtaFv2()
		if err != nil {
			return nil, err
		}
		msg_hats[J+1] = e

		randomnessC, err := pp.sampleRandomnessRv2()
		if err != nil {
			return nil, err
		}
		r_hat := pp.NTTPolyCVec(randomnessC)

		// b_hat =B * r_hat
		b_hat := pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, r_hat, pp.paramKC, pp.paramLC)

		for i := 0; i < n2; i++ { // n2 = J+2
			c_hats[i] = pp.PolyCNTTAdd(
				pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[i+1], r_hat, pp.paramLC),
				&PolyCNTT{coeffs: msg_hats[i]},
			)
		}

		//	todo: check the scope of u_p in theory
		u_p := make([]int64, pp.paramDC) // todo: make sure that (eta_f, d) will not make the value of u_p[i] over int32
		u_p_tmp := make([]int64, pp.paramDC)

		seed_binM, err := Hash(pp.collectBytesForCoinbase2(cbTxCon, b_hat, c_hats)) // todo_DONE: compute the seed using hash function on (b_hat, c_hats).

		if err != nil {
			return nil, err
		}
		binM, err := expandBinaryMatrix(seed_binM, pp.paramDC, pp.paramDC)
		if err != nil {
			return nil, err
		}
		// todo: check B f + e
		for i := 0; i < pp.paramDC; i++ {
			u_p_tmp[i] = e[i]
			for j := 0; j < pp.paramDC; j++ {
				if (binM[i][j/8]>>(j%8))&1 == 1 {
					u_p_tmp[i] = u_p_tmp[i] + f[j]
				}
			}

			infNorm := u_p_tmp[i]
			if infNorm < 0 {
				infNorm = -infNorm
			}
			if infNorm > pp.paramEtaF-int64(J-1) {
				goto cbTxGenJ2Restart
			}

			u_p[i] = reduceInt64(u_p_tmp[i], pp.paramQC) // todo: 202203 Do need reduce?
		}

		u_hats[1] = make([]int64, pp.paramDC)
		for i := 0; i < pp.paramDC; i++ {
			u_hats[1][i] = 0
		}
		u_hats[2] = u_p

		n1 := n
		rprlppi, pi_err := pp.rpulpProve(cbTxCon, cmts, cmt_rs, n, b_hat, r_hat, c_hats, msg_hats, n2, n1, RpUlpTypeCbTx2, binM, 0, J, 3, u_hats)

		if pi_err != nil {
			return nil, pi_err
		}

		retcbTx.TxWitness = &CbTxWitnessv2{
			b_hat:      b_hat,
			c_hats:     c_hats,
			u_p:        u_p,
			rpulpproof: rprlppi,
		}
	}

	return retcbTx, nil
}

// CoinbaseTxVerify reports whether a coinbase transaction is legal.
func (pp *PublicParameter) CoinbaseTxVerify(cbTx *CoinbaseTxv2) bool {
	if cbTx == nil {
		return false
	}

	V := uint64(1)<<pp.paramN - 1

	if cbTx.Vin > V {
		return false
	}

	if cbTx.OutputTxos == nil || len(cbTx.OutputTxos) == 0 {
		return false
	}

	if cbTx.TxWitness == nil {
		return false
	}

	J := len(cbTx.OutputTxos)
	if J > pp.paramJ {
		return false
	}

	/*	// todo_DONE: check no repeated dpk in cbTx.OutputTxos
		dpkMap := make(map[*PublicKey]struct{})
		for i := 0; i < len(cbTx.OutputTxos); i++ {
			if _, ok := dpkMap[cbTx.OutputTxos[i].PublicKey]; !ok {
				dpkMap[cbTx.OutputTxos[i].PublicKey] = struct{}{}
			} else {
				return false
			}
		}*/
	// todo: check cbTx.OutputTxos[j].cmt is well-formed

	cbTxCon := make([]byte, 0, 8)
	tw := bytes.NewBuffer(cbTxCon)
	tw.WriteByte(byte(cbTx.Vin >> 0))
	tw.WriteByte(byte(cbTx.Vin >> 8))
	tw.WriteByte(byte(cbTx.Vin >> 16))
	tw.WriteByte(byte(cbTx.Vin >> 24))
	tw.WriteByte(byte(cbTx.Vin >> 32))
	tw.WriteByte(byte(cbTx.Vin >> 40))
	tw.WriteByte(byte(cbTx.Vin >> 48))
	tw.WriteByte(byte(cbTx.Vin >> 56))
	for i := 0; i < J; i++ {
		serializedTxo, err := pp.TxoSerialize(cbTx.OutputTxos[i])
		if err != nil {
			log.Fatalln(err)
			return false
		}
		_, err = tw.Write(serializedTxo)
		if err != nil {
			log.Fatalf("error in serializing txo")
			return false
		}
	}
	if J == 1 {
		if cbTx.TxWitness.b_hat != nil || cbTx.TxWitness.c_hats != nil || cbTx.TxWitness.u_p != nil {
			return false
		}
		if cbTx.TxWitness.rpulpproof == nil {
			return false
		}
		if cbTx.TxWitness.rpulpproof.c_waves != nil || cbTx.TxWitness.rpulpproof.c_hat_g != nil ||
			cbTx.TxWitness.rpulpproof.psi != nil || cbTx.TxWitness.rpulpproof.phi != nil ||
			cbTx.TxWitness.rpulpproof.cmt_zs != nil {
			return false
		}
		if cbTx.TxWitness.rpulpproof.chseed == nil || cbTx.TxWitness.rpulpproof.zs == nil {
			return false
		}
		// todo check the well-form of chseed

		// check the well-formof zs
		if len(cbTx.TxWitness.rpulpproof.zs) != pp.paramK {
			return false
		}
		// infNorm of z^t
		bound := pp.paramEtaC - int64(pp.paramBetaC)
		for t := 0; t < pp.paramK; t++ {
			if pp.NTTInvPolyCVec(cbTx.TxWitness.rpulpproof.zs[t]).infNorm() > bound {
				return false
			}
		}

		ws := make([]*PolyCNTTVec, pp.paramK)
		deltas := make([]*PolyCNTT, pp.paramK)

		chtmp, err := pp.expandChallengeC(cbTx.TxWitness.rpulpproof.chseed)
		if err != nil {
			return false
		}
		ch := pp.NTTPolyC(chtmp)
		mtmp := intToBinary(cbTx.Vin, pp.paramDC)
		//msg := pp.NTTInRQc(&Polyv2{coeffs1: mtmp})
		msg := &PolyCNTT{coeffs: mtmp}
		for t := 0; t < pp.paramK; t++ {
			sigma_t_ch := pp.sigmaPowerPolyCNTT(ch, t)

			ws[t] = pp.PolyCNTTVecSub(
				pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, cbTx.TxWitness.rpulpproof.zs[t], pp.paramKC, pp.paramLC),
				pp.PolyCNTTVecScaleMul(sigma_t_ch, cbTx.OutputTxos[0].ValueCommitment.b, pp.paramKC),
				pp.paramKC,
			)
			deltas[t] = pp.PolyCNTTSub(
				pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[0], cbTx.TxWitness.rpulpproof.zs[t], pp.paramLC),
				pp.PolyCNTTMul(
					sigma_t_ch,
					pp.PolyCNTTSub(cbTx.OutputTxos[0].c, msg),
				), // Modified?
			)
		}

		seed_ch, err := Hash(pp.collectBytesForCoinbase1(cbTxCon, ws, deltas))
		if err != nil {
			return false
		}
		if bytes.Compare(seed_ch, cbTx.TxWitness.rpulpproof.chseed) != 0 {
			return false
		}
	} else {
		// check the well-formness of cbTx.TxWitness
		if cbTx.TxWitness.b_hat == nil || cbTx.TxWitness.c_hats == nil || cbTx.TxWitness.u_p == nil || cbTx.TxWitness.rpulpproof == nil {
			return false
		}

		n := J
		n2 := J + 2

		if len(cbTx.TxWitness.c_hats) != n2 {
			return false
		}

		//	infNorm of u'
		infNorm := int64(0)
		if len(cbTx.TxWitness.u_p) != pp.paramDC {
			return false
		}
		for i := 0; i < pp.paramDC; i++ {
			infNorm = cbTx.TxWitness.u_p[i]
			if infNorm < 0 {
				infNorm = -infNorm
			}

			if infNorm >= (pp.paramEtaF - int64(J-1)) { // todo: q/12 or eta_f - (J-1)
				return false
			}
		}

		seed_binM, err := Hash(pp.collectBytesForCoinbase2(cbTxCon, cbTx.TxWitness.b_hat, cbTx.TxWitness.c_hats)) // todo_DONE: compute the seed using hash function on (b_hat, c_hats).
		if err != nil {
			return false
		}
		binM, err := expandBinaryMatrix(seed_binM, pp.paramDC, pp.paramDC)
		if err != nil {
			return false
		}

		u_hats := make([][]int64, 3)
		u_hats[0] = intToBinary(cbTx.Vin, pp.paramDC)
		u_hats[1] = make([]int64, pp.paramDC)
		u_hats[2] = cbTx.TxWitness.u_p

		cmts := make([]*ValueCommitment, n)
		for i := 0; i < n; i++ {
			cmts[i] = cbTx.OutputTxos[i].ValueCommitment
		}

		n1 := n
		flag := pp.rpulpVerify(cbTxCon, cmts, n, cbTx.TxWitness.b_hat, cbTx.TxWitness.c_hats, n2, n1, RpUlpTypeCbTx2, binM, 0, J, 3, u_hats, cbTx.TxWitness.rpulpproof)
		return flag
	}

	return true
}

func (pp *PublicParameter) collectBytesForCoinbase1(premsg []byte, ws []*PolyCNTTVec, deltas []*PolyCNTT) []byte {
	tmp := make([]byte, 0, pp.paramDC*4+(pp.paramKC+1)*pp.paramDC*4+(pp.paramKC+1)*pp.paramDC*4)
	w := bytes.NewBuffer(tmp)
	appendPolyCNTTToBytes := func(a *PolyCNTT) {
		for k := 0; k < pp.paramDC; k++ {
			w.WriteByte(byte(a.coeffs[k] >> 0))
			w.WriteByte(byte(a.coeffs[k] >> 8))
			w.WriteByte(byte(a.coeffs[k] >> 16))
			w.WriteByte(byte(a.coeffs[k] >> 24))
			w.WriteByte(byte(a.coeffs[k] >> 32))
			w.WriteByte(byte(a.coeffs[k] >> 40))
			w.WriteByte(byte(a.coeffs[k] >> 48))
			w.WriteByte(byte(a.coeffs[k] >> 56))
		}
	}
	// premsg
	w.Write(premsg)

	for i := 0; i < len(ws); i++ {
		for j := 0; j < len(ws[i].polyCNTTs); j++ {
			appendPolyCNTTToBytes(ws[i].polyCNTTs[i])
		}
	}

	for i := 0; i < len(deltas); i++ {
		appendPolyCNTTToBytes(deltas[i])
	}
	return tmp
}

// collectBytesForCoinbase2 is an auxiliary function for CoinbaseTxGen and CoinbaseTxVerify to collect some information into a byte slice
func (pp *PublicParameter) collectBytesForCoinbase2(premsg []byte, b_hat *PolyCNTTVec, c_hats []*PolyCNTT) []byte {
	res := make([]byte, 0, pp.paramKC*pp.paramDC*4+pp.paramDC*4*len(c_hats))
	w := bytes.NewBuffer(res)
	appendPolyCNTTToBytes := func(a *PolyCNTT) {
		for k := 0; k < pp.paramDC; k++ {
			w.WriteByte(byte(a.coeffs[k] >> 0))
			w.WriteByte(byte(a.coeffs[k] >> 8))
			w.WriteByte(byte(a.coeffs[k] >> 16))
			w.WriteByte(byte(a.coeffs[k] >> 24))
			w.WriteByte(byte(a.coeffs[k] >> 32))
			w.WriteByte(byte(a.coeffs[k] >> 40))
			w.WriteByte(byte(a.coeffs[k] >> 48))
			w.WriteByte(byte(a.coeffs[k] >> 56))
		}
	}
	// premsg
	w.Write(premsg)
	// b_hat
	for i := 0; i < pp.paramKC; i++ {
		appendPolyCNTTToBytes(b_hat.polyCNTTs[i])
	}
	// c_hats
	for i := 0; i < len(c_hats); i++ {
		appendPolyCNTTToBytes(c_hats[i])
	}
	return res
}

func (pp *PublicParameter) TransferTxGen(inputDescs []*TxInputDescv2, outputDescs []*TxOutputDescv2, fee uint64, txMemo []byte) (trTx *TransferTxv2, err error) {
	//	check the well-formness of the inputs and outputs
	if len(inputDescs) == 0 || len(outputDescs) == 0 {
		return nil, errors.New("some information is empty")
	}

	if len(inputDescs) > pp.paramI {
		return nil, errors.New("too many inputs") //Todo: may define a new error type?
	}
	if len(outputDescs) > pp.paramJ {
		return nil, errors.New("too many outputs")
	}

	V := uint64(1)<<pp.paramN - 1

	if fee > V {
		return nil, errors.New("the transaction fee is more than V")
	}

	//	check on the outputDesc is simple, so check it first
	outputTotal := fee
	apks := make([]*AddressPublicKey, len(outputDescs))
	for i, outputDescItem := range outputDescs {
		if outputDescItem.value > V {
			return nil, errors.New("the value is more than max value")
		}
		outputTotal = outputTotal + outputDescItem.value
		if outputTotal > V {
			return nil, errors.New("the value is more than max value")
		}

		if outputDescItem.serializedAPk == nil || outputDescItem.serializedVPk == nil {
			return nil, errors.New("the address public key or value publci key is nil")
		}
		apks[i], err = pp.AddressPublicKeyDeserialize(outputDescItem.serializedAPk)
		if err != nil || apks[i] == nil {
			return nil, errors.New("the apk is not well-form")
		}
	}

	I := len(inputDescs)
	J := len(outputDescs)
	cmtrs_in := make([]*PolyCNTTVec, I)
	msgs_in := make([][]int64, I)

	inputTotal := uint64(0)
	asks := make([]*AddressSecretKey, len(outputDescs))
	for i, inputDescItem := range inputDescs {
		if inputDescItem.value > V {
			return nil, errors.New("the value is more than max value")
		}
		inputTotal = inputTotal + inputDescItem.value
		if inputTotal > V {
			return nil, errors.New("the value is more than max value")
		}

		if len(inputDescItem.txoList) == 0 {
			return nil, errors.New("the transaction output list is empty")
		}
		if inputDescItem.sidx < 0 || inputDescItem.sidx >= len(inputDescItem.txoList) {
			return nil, errors.New("the index is not suitable")
		}
		/*		if inputDescItem.txoList[inputDescItem.sidx].ask == nil || inputDescItem.sk == nil {
				return nil, errors.New("some information is empty")
			}*/
		if inputDescItem.txoList[inputDescItem.sidx].AddressPublicKey == nil || inputDescItem.serializedASksp == nil || inputDescItem.txoList[inputDescItem.sidx].ValueCommitment == nil {
			return nil, errors.New("some information is empty")
		}
		asks[i] = &AddressSecretKey{}
		asks[i].AddressSecretKeySp, err = pp.AddressSecretKeySpDeserialize(inputDescItem.serializedASksp)
		if err != nil {
			return nil, err
		}
		asks[i].AddressSecretKeySn, err = pp.AddressSecretKeySnDeserialize(inputDescItem.serializedASksn)
		if err != nil || asks[i] == nil {
			return nil, err
		}

		if asks[i].CheckMatchPublciKey(inputDescItem.txoList[inputDescItem.sidx].AddressPublicKey, pp) == false {
			return nil, errors.New("the address secret key and correspdong public key does not match")
		}

		// run kem.decaps to get kappa
		kappa, err := pqringctkem.Decaps(pp.paramKem, inputDescItem.txoList[inputDescItem.sidx].CkemSerialzed, inputDescItem.serializedVSk)
		if err != nil {
			return nil, err
		}

		//	msgs_in[i] <-- inputDescItem.value
		msgs_in[i] = intToBinary(inputDescItem.value, pp.paramDC)
		// then get cmtrs_in[i]
		cmtrtmp, err := pp.expandRandomnessC(kappa)
		if err != nil {
			return nil, err
		}
		cmtrs_in[i] = pp.NTTPolyCVec(cmtrtmp)
		b := pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, cmtrs_in[i], pp.paramKC, pp.paramLC)
		c := pp.PolyCNTTAdd(
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[0], cmtrs_in[i], pp.paramLC),
			&PolyCNTT{msgs_in[i]})

		// and check the validity
		if !pp.PolyCNTTVecEqualCheck(b, inputDescItem.txoList[inputDescItem.sidx].b) {
			return nil, errors.New("fail to receive some transaction output : the computed commitment is not equal to input")
		}

		if !pp.PolyCNTTEqualCheck(c, inputDescItem.txoList[inputDescItem.sidx].c) {
			return nil, errors.New("fail to receive some transaction output : the computed commitment is not equal to input")
		}
	}

	if outputTotal != inputTotal {
		return nil, errors.New("the total coin value is not balance")
	}

	rettrTx := &TransferTxv2{}
	rettrTx.Inputs = make([]*TrTxInputv2, I)
	rettrTx.OutputTxos = make([]*Txo, J)
	rettrTx.Fee = fee
	rettrTx.TxMemo = txMemo

	cmtrs_out := make([]*PolyCNTTVec, J)
	for j := 0; j < J; j++ {
		txo, cmtr, err := pp.txoGen(apks[j], outputDescs[j].serializedVPk, outputDescs[j].value)
		if err != nil {
			return nil, err
		}
		rettrTx.OutputTxos[j] = txo
		cmtrs_out[j] = cmtr
	}

	ma_ps := make([]*PolyANTT, I)
	cmt_ps := make([]*ValueCommitment, I)
	cmtr_ps := make([]*PolyCNTTVec, I)
	for i := 0; i < I; i++ {
		// extract this as a function named SerialNumberCompute
		m_r := pp.ExpandKIDR(inputDescs[i].txoList[inputDescs[i].sidx])
		ma_ps[i] = pp.PolyANTTAdd(asks[i].ma, m_r)
		sn := pp.SerialNumberCompute(ma_ps[i])

		rettrTx.Inputs[i] = &TrTxInputv2{
			TxoList:      inputDescs[i].txoList,
			SerialNumber: sn,
		}

		tmprp, err := pp.sampleRandomnessRv2()
		if err != nil {
			return nil, err
		}
		cmtr_ps[i] = pp.NTTPolyCVec(tmprp)
		cmt_ps[i] = &ValueCommitment{}
		cmt_ps[i].b = pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, cmtr_ps[i], pp.paramKC, pp.paramLC)
		cmt_ps[i].c = pp.PolyCNTTAdd(
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[0], cmtr_ps[i], pp.paramLC),
			&PolyCNTT{coeffs: msgs_in[i]},
		)
	}

	/*	rettrTx.TxWitness = &TrTxWitnessv2{
		b_hat:      nil,
		c_hats:     nil,
		u_p:        nil,
		rpulpproof: nil,
		cmtps:      cmt_in_ips,
		elrsSigs:   nil,
	}*/

	msgTrTxCon, err := pp.TransferTxSerialize(rettrTx, false)
	if msgTrTxCon == nil || err != nil {
		return nil, errors.New("error in rettrTx.Serialize ")
	}
	//msgTrTxConExt := msgTrTxCon	// todo: not need to do. append cmt_ps

	elrsSigs := make([]*elrsSignaturev2, I)
	for i := 0; i < I; i++ {
		elrsSigs[i], err = pp.ELRSSign(inputDescs[i].txoList, ma_ps[i], cmt_ps[i], msgTrTxCon,
			inputDescs[i].sidx, asks[i].s, cmtrs_in[i], cmtr_ps[i])
		if err != nil {
			return nil, errors.New("fail to generate the extend linkable signature")
		}
	}

	n := I + J
	n2 := I + J + 2
	if I > 1 {
		n2 = I + J + 4
	}

	c_hats := make([]*PolyCNTT, n2)
	msg_hats := make([][]int64, n2)

	cmtrs := make([]*PolyCNTTVec, n)
	cmts := make([]*ValueCommitment, n)
	for i := 0; i < I; i++ {
		cmts[i] = cmt_ps[i]
		cmtrs[i] = cmtr_ps[i]
		msg_hats[i] = msgs_in[i]
	}
	for j := 0; j < J; j++ {
		cmts[I+j] = rettrTx.OutputTxos[j].ValueCommitment
		cmtrs[I+j] = cmtrs_out[j]
		msg_hats[I+j] = intToBinary(outputDescs[j].value, pp.paramDC)
	}

	randomnessC, err := pp.sampleRandomnessRv2()
	if err != nil {
		return nil, err
	}
	r_hat := pp.NTTPolyCVec(randomnessC)
	b_hat := pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, r_hat, pp.paramKC, pp.paramLC)
	for i := 0; i < n; i++ { // n = I+J
		c_hats[i] = pp.PolyCNTTAdd(
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[i+1], r_hat, pp.paramLC),
			&PolyCNTT{coeffs: msg_hats[i]},
		)
	}

	//	fee
	u := intToBinary(fee, pp.paramDC)

	if I == 1 {
		//	n2 = n+2
		//	f is the carry vector, such that, m_1 = m_2+ ... + m_n + u
		//	f[0] = 0, and for i=1 to d-1,
		//	m_0[i-1] + 2 f[i] = m_1[i-1] + .. + m_{n-1}[i-1] + u[i-1] + f[i-1],
		//	m_0[d-1] 		  = m_1[d-1] + .. + m_{n-1}[d-1] + f[d-1],
		f := make([]int64, pp.paramDC)
		f[0] = 0
		for i := 1; i < pp.paramDC; i++ {
			tmp := int64(0)
			for j := 1; j < n; j++ {
				tmp = tmp + msg_hats[j][i-1]
			}
			f[i] = (tmp + u[i-1] + f[i-1] - msg_hats[0][i-1]) >> 1
		}
		msg_hats[n] = f
		c_hats[n] = pp.PolyCNTTAdd(
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[n+1], r_hat, pp.paramLC),
			&PolyCNTT{coeffs: msg_hats[n]},
		)

	trTxGenI1Restart:
		e, err := pp.sampleUniformWithinEtaFv2()
		if err != nil {
			return nil, err
		}
		msg_hats[n+1] = e
		c_hats[n+1] = pp.PolyCNTTAdd(
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[n+2], r_hat, pp.paramLC),
			&PolyCNTT{coeffs: msg_hats[n+1]},
		)

		// todo: check the scope of u_p in theory
		u_p := make([]int64, pp.paramDC)
		u_p_temp := make([]int64, pp.paramDC)                                         // todo: make sure that (eta_f, d) will not make the value of u_p[i] over int32
		seed_binM, err := Hash(pp.collectBytesForTransfer(msgTrTxCon, b_hat, c_hats)) // todo:20220317
		if err != nil {
			return nil, err
		}
		binM, err := expandBinaryMatrix(seed_binM, pp.paramDC, pp.paramDC)
		if err != nil {
			return nil, err
		}
		// todo: check B f + e
		// up = B * f + e
		for i := 0; i < pp.paramDC; i++ {
			u_p_temp[i] = e[i]
			for j := 0; j < pp.paramDC; j++ {
				if (binM[i][j/8]>>(j%8))&1 == 1 {
					u_p_temp[i] += f[j]
				}
			}

			infNorm := u_p_temp[i]
			if infNorm < 0 {
				infNorm = -infNorm
			}

			if infNorm > (pp.paramEtaF - int64(J)) {
				goto trTxGenI1Restart
			}

			u_p[i] = reduceInt64(u_p_temp[i], pp.paramQC) // todo: need to confirm
		}

		u_hats := make([][]int64, 3)
		u_hats[0] = u
		u_hats[1] = make([]int64, pp.paramDC)
		for i := 0; i < pp.paramDC; i++ {
			u_hats[1][i] = 0
		}
		u_hats[2] = u_p

		n1 := n
		rpulppi, pi_err := pp.rpulpProve(msgTrTxCon, cmts, cmtrs, n, b_hat, r_hat, c_hats, msg_hats, n2, n1, RpUlpTypeTrTx1, binM, I, J, 3, u_hats)

		if pi_err != nil {
			return nil, pi_err
		}

		rettrTx.TxWitness = &TrTxWitnessv2{
			ma_ps,
			cmt_ps,
			elrsSigs,
			b_hat,
			c_hats,
			u_p,
			rpulppi,
		}
	} else {
		//	n2 = n+4
		msg_hats[n] = intToBinary(inputTotal, pp.paramDC) //	v_in
		c_hats[n] = pp.PolyCNTTAdd(
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[n+1], r_hat, pp.paramLC),
			&PolyCNTT{coeffs: msg_hats[n]},
		)
		//	f1 is the carry vector, such that, m_0 + m_1+ ... + m_{I-1} = m_{n}
		//	f1[0] = 0, and for i=1 to d-1,
		//	m_0[i-1] + .. + m_{I-1}[i-1] + f1[i-1] = m_n[i-1] + 2 f[i] ,
		//	m_0[d-1] + .. + m_{I-1}[d-1] + f1[d-1] = m_n[d-1] ,
		f1 := make([]int64, pp.paramDC)
		f1[0] = 0
		for i := 1; i < pp.paramDC; i++ {
			tmp := int64(0)
			for j := 0; j < I; j++ {
				tmp = tmp + msg_hats[j][i-1]
			}
			f1[i] = (tmp + f1[i-1] - msg_hats[n][i-1]) >> 1
		}
		msg_hats[n+1] = f1
		c_hats[n+1] = pp.PolyCNTTAdd(
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[n+2], r_hat, pp.paramLC),
			&PolyCNTT{coeffs: msg_hats[n+1]},
		)

		//	f2 is the carry vector, such that, m_I + m_{I+1}+ ... + m_{(I+J)-1} + u = m_{n}
		//	f2[0] = 0, and for i=1 to d-1,
		//	m_I[i-1] + .. + m_{I+J-1}[i-1] + u[i-1] + f2[i-1] = m_n[i-1] + 2 f[i] ,
		//	m_I[d-1] + .. + m_{I+J-1}[d-1] + u[d-1] + f2[d-1] = m_n[d-1] ,
		f2 := make([]int64, pp.paramDC)
		f2[0] = 0
		for i := 1; i < pp.paramDC; i++ {
			tmp := int64(0)
			for j := 0; j < J; j++ {
				tmp = tmp + msg_hats[I+j][i-1]
			}
			f2[i] = (tmp + u[i-1] + f2[i-1] - msg_hats[n][i-1]) >> 1
		}
		msg_hats[n+2] = f2
		c_hats[n+2] = pp.PolyCNTTAdd(
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[n+3], r_hat, pp.paramLC),
			&PolyCNTT{coeffs: msg_hats[n+2]},
		)
	trTxGenI2Restart:
		e, err := pp.sampleUniformWithinEtaFv2()
		if err != nil {
			return nil, err
		}
		msg_hats[n+3] = e
		c_hats[n+3] = pp.PolyCNTTAdd(
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[n+4], r_hat, pp.paramLC),
			&PolyCNTT{coeffs: msg_hats[n+3]},
		)

		// todo: check the scope of u_p in theory
		u_p := make([]int64, pp.paramDC)
		u_p_temp := make([]int64, pp.paramDC)                                         // todo: make sure that (eta_f, d) will not make the value of u_p[i] over int32
		seed_binM, err := Hash(pp.collectBytesForTransfer(msgTrTxCon, b_hat, c_hats)) // todo: confirm 20220317
		if err != nil {
			return nil, err
		}
		binM, err := expandBinaryMatrix(seed_binM, pp.paramDC, 2*pp.paramDC)
		if err != nil {
			return nil, err
		}
		// todo: check B (f_1 || f_2) + e
		betaF := I
		if J+1 > betaF {
			betaF = J + 1
		}
		betaF = betaF - 1

		for i := 0; i < pp.paramDC; i++ {
			u_p_temp[i] = e[i]
			for j := 0; j < pp.paramDC; j++ {
				//	u_p_temp[i] = u_p_temp[i] + int64(e[j])

				if (binM[i][j/8]>>(j%8))&1 == 1 {
					u_p_temp[i] += f1[j]
				}
				if (binM[i][(pp.paramDC+j)/8]>>((pp.paramDC+j)%8))&1 == 1 {
					u_p_temp[i] += f2[j]
				}
			}

			infNorm := u_p_temp[i]
			if infNorm < 0 {
				infNorm = -infNorm
			}

			if infNorm > (pp.paramEtaF - int64(betaF)) {
				goto trTxGenI2Restart
			}

			u_p[i] = reduceInt64(u_p_temp[i], pp.paramQC) // todo: confirm whether need to reduce
		}

		u_hats := make([][]int64, 5)
		u_hats[0] = make([]int64, pp.paramDC)
		// todo_DONE: -u
		u_hats[1] = make([]int64, pp.paramDC)
		for i := 0; i < pp.paramDC; i++ {
			u_hats[1][i] = -u[i]
		}
		u_hats[2] = make([]int64, pp.paramDC)
		u_hats[3] = make([]int64, pp.paramDC)
		u_hats[4] = u_p
		for i := 0; i < pp.paramDC; i++ {
			u_hats[0][i] = 0
			u_hats[2][i] = 0
			u_hats[3][i] = 0
		}

		n1 := n + 1
		rpulppi, pi_err := pp.rpulpProve(msgTrTxCon, cmts, cmtrs, n, b_hat, r_hat, c_hats, msg_hats, n2, n1, RpUlpTypeTrTx2, binM, I, J, 5, u_hats)

		if pi_err != nil {
			return nil, pi_err
		}

		rettrTx.TxWitness = &TrTxWitnessv2{
			ma_ps,
			cmt_ps,
			elrsSigs,
			b_hat,
			c_hats,
			u_p,
			rpulppi,
		}
	}
	return rettrTx, err
}

// TransferTxVerify reports whether a transfer transaction is legal.
func (pp *PublicParameter) TransferTxVerify(trTx *TransferTxv2) bool {
	if trTx == nil {
		return false
	}

	I := len(trTx.Inputs)
	J := len(trTx.OutputTxos)

	if I <= 0 || I > pp.paramI {
		return false
	}
	if J <= 0 || J > pp.paramJ {
		return false
	}

	//	todo: check the well-form of TxWitness

	//	check the ring signatures
	msgTrTxCon, err := pp.TransferTxSerialize(trTx, false)
	if msgTrTxCon == nil || err != nil {
		return false
	}
	/*	msgTrTxConHash, err := Hash(msgTrTxCon)
		if err != nil {
			return false
		}*/
	for i := 0; i < I; i++ {
		//	check the validity of sigma_{lrs,i}
		sn := pp.SerialNumberCompute(trTx.TxWitness.ma_ps[i])
		if !bytes.Equal(trTx.Inputs[i].SerialNumber, sn) {
			return false
		}

		if !pp.ELRSVerify(trTx.Inputs[i].TxoList, trTx.TxWitness.ma_ps[i], trTx.TxWitness.cmt_ps[i], msgTrTxCon, trTx.TxWitness.elrsSigs[i]) {
			return false
		}
	}

	// check the balance proof
	n := I + J
	cmts := make([]*ValueCommitment, n)
	for i := 0; i < I; i++ {
		cmts[i] = trTx.TxWitness.cmt_ps[i]
	}
	for j := 0; j < J; j++ {
		cmts[I+j] = trTx.OutputTxos[j].ValueCommitment
	}

	u := intToBinary(trTx.Fee, pp.paramDC)

	if I == 1 {
		n2 := n + 2
		n1 := n

		betaF := J

		//	todo: consider with TransferTxGen
		for i := 0; i < len(trTx.TxWitness.u_p); i++ {
			infNorm := trTx.TxWitness.u_p[i]
			if infNorm < 0 {
				infNorm = -infNorm
			}
			if infNorm > (pp.paramEtaF - int64(betaF)) {
				return false
			}
		}

		seed_binM, err := Hash(pp.collectBytesForTransfer(msgTrTxCon, trTx.TxWitness.b_hat, trTx.TxWitness.c_hats)) // todo_DONE: compute the seed using hash function on (b_hat, c_hats).
		if err != nil {
			return false
		}
		binM, err := expandBinaryMatrix(seed_binM, pp.paramDC, pp.paramDC)
		if err != nil {
			return false
		}

		u_hats := make([][]int64, 3)
		u_hats[0] = u
		u_hats[1] = make([]int64, pp.paramDC)
		u_hats[2] = trTx.TxWitness.u_p
		for i := 0; i < pp.paramDC; i++ {
			u_hats[1][i] = 0
		}

		flag := pp.rpulpVerify(msgTrTxCon, cmts, n, trTx.TxWitness.b_hat, trTx.TxWitness.c_hats, n2, n1, RpUlpTypeTrTx1, binM, I, J, 3, u_hats, trTx.TxWitness.rpulpproof)
		if !flag {
			return false
		}
	} else {
		//	I >= 2
		n2 := n + 4
		n1 := n + 1

		betaF := I
		if J+1 > betaF {
			betaF = J + 1
		}
		betaF = betaF - 1

		//	todo: consider with TransferTxGen
		for i := 0; i < len(trTx.TxWitness.u_p); i++ {
			infNorm := trTx.TxWitness.u_p[i]
			if infNorm < 0 {
				infNorm = -infNorm
			}
			if infNorm > (pp.paramEtaF - int64(betaF)) {
				return false
			}
		}

		seed_binM, err := Hash(pp.collectBytesForTransfer(msgTrTxCon, trTx.TxWitness.b_hat, trTx.TxWitness.c_hats)) // todo_DONE: compute the seed using hash function on (b_hat, c_hats).
		binM, err := expandBinaryMatrix(seed_binM, pp.paramDC, 2*pp.paramDC)
		if err != nil {
			return false
		}

		u_hats := make([][]int64, 5)
		u_hats[0] = make([]int64, pp.paramDC)
		// todo_DONE: -u
		u_hats[1] = make([]int64, pp.paramDC)
		for i := 0; i < len(u_hats[1]); i++ {
			u_hats[1][i] = -u[i]
		}
		u_hats[2] = make([]int64, pp.paramDC)
		u_hats[3] = make([]int64, pp.paramDC)
		u_hats[4] = trTx.TxWitness.u_p
		for i := 0; i < pp.paramDC; i++ {
			u_hats[0][0] = 0
			u_hats[2][0] = 0
			u_hats[3][0] = 0
		}

		flag := pp.rpulpVerify(msgTrTxCon, cmts, n, trTx.TxWitness.b_hat, trTx.TxWitness.c_hats, n2, n1, RpUlpTypeTrTx2, binM, I, J, 5, u_hats, trTx.TxWitness.rpulpproof)
		if !flag {
			return false
		}
	}

	return true
}

// todo: add input premsg
func (pp *PublicParameter) collectBytesForTransfer(premsg []byte, b_hat *PolyCNTTVec, c_hats []*PolyCNTT) []byte {
	res := make([]byte, pp.paramKC*pp.paramDC*4+pp.paramDC*4*len(c_hats))
	w := bytes.NewBuffer(res)
	appendPolyCNTTToBytes := func(a *PolyCNTT) {
		for k := 0; k < pp.paramDC; k++ {
			w.WriteByte(byte(a.coeffs[k] >> 0))
			w.WriteByte(byte(a.coeffs[k] >> 8))
			w.WriteByte(byte(a.coeffs[k] >> 16))
			w.WriteByte(byte(a.coeffs[k] >> 24))
			w.WriteByte(byte(a.coeffs[k] >> 32))
			w.WriteByte(byte(a.coeffs[k] >> 40))
			w.WriteByte(byte(a.coeffs[k] >> 48))
			w.WriteByte(byte(a.coeffs[k] >> 56))
		}
	}
	// premsg
	w.Write(premsg)
	// b_hat
	for i := 0; i < pp.paramKC; i++ {
		appendPolyCNTTToBytes(b_hat.polyCNTTs[i])
	}
	// c_hats
	for i := 0; i < len(c_hats); i++ {
		appendPolyCNTTToBytes(c_hats[i])
	}
	return res
}

func (pp *PublicParameter) SerialNumberCompute(a *PolyANTT) []byte {
	tmp := make([]byte, pp.paramDA*8)
	for k := 0; k < pp.paramDA; k++ {
		tmp = append(tmp, byte(a.coeffs[k]>>0))
		tmp = append(tmp, byte(a.coeffs[k]>>8))
		tmp = append(tmp, byte(a.coeffs[k]>>16))
		tmp = append(tmp, byte(a.coeffs[k]>>24))
		tmp = append(tmp, byte(a.coeffs[k]>>32))
		tmp = append(tmp, byte(a.coeffs[k]>>40))
		tmp = append(tmp, byte(a.coeffs[k]>>48))
		tmp = append(tmp, byte(a.coeffs[k]>>56))

	}
	res, err := Hash(tmp)
	if err != nil {
		log.Fatalln("Error call Hash() in SerialNumberCompute")
	}
	return res
}

func (pp *PublicParameter) LedgerTXOSerialNumberGen(txo []byte, txolid []byte, skma []byte) []byte {
	t := make([]byte, 0, len(txo)+len(txolid))
	t = append(t, txo...)
	t = append(t, txolid...)
	seed, err := Hash(t)
	if err != nil {
		return nil
	}
	got := rejectionUniformWithQa(seed, pp.paramDA, pp.paramQA)
	m_r := &PolyANTT{coeffs: got}

	r := bytes.NewReader(skma)
	ma, err := pp.ReadPolyANTT(r)
	if err != nil {
		return nil
	}
	ma_ps := pp.PolyANTTAdd(ma, m_r)
	sn := pp.SerialNumberCompute(ma_ps)
	return sn[:]
}
