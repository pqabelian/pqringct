package pqringct

import (
	"bytes"
	"errors"
	"github.com/cryptosuite/kyber-go/kyber"
	"io"
)

/*func NewPolyNTTVec(rowlength int, colLength int) *PolyNTTVec {
	res := make([]*PolyNTT, rowlength)
	for i := 0; i < rowlength; i++ {
		res[i] = NewPolyNTT(colLength)
	}
	return &PolyNTTVec{polyNTTs: res}
}*/

/*
This file defines all public constants and interfaces of PQRingCT.
*/

type MasterPublicKey struct {
	pkkem *kyber.PublicKey
	t     *PolyNTTVec // directly in NTT form
}

type MasterSecretViewKey struct {
	skkem *kyber.SecretKey
}

type MasterSecretSignKey struct {
	s *PolyNTTVec
}

type CbTxWitness struct {
	b_hat      *PolyNTTVec
	c_hats     []*PolyNTT
	u_p        []int32
	rpulpproof *rpulpProof
}

func (cbTxWitness *CbTxWitness) SerializeSize() uint32 {
	// todo
	return 1
}

func (cbTxWitness *CbTxWitness) Serialize() []byte {
	// todo
	return nil
}

func (cbTxWitness *CbTxWitness) Deserialize(serializedTxWitness []byte) error {
	// todo
	return nil
}

type CoinbaseTx struct {
	//	Version uint32

	Vin        uint64
	OutputTxos []*TXO

	TxWitness *CbTxWitness
}

type TrTxInput struct {
	TxoList []*TXO
	//SerialNumber []byte
	SerialNumber []byte // todo: change to a hash value
}

func (trTxInput TrTxInput) Serialize(w io.Writer) error {
	// write txoList size
	count := uint64(len(trTxInput.TxoList))
	err := WriteVarInt(w, count)
	if err != nil {
		return err
	}
	// write txoList
	for _, txo := range trTxInput.TxoList {
		err := txo.Serialize(w)
		if err != nil {
			return err
		}
	}

	// write serialNumber
	_, err = w.Write(trTxInput.SerialNumber)
	if err != nil {
		return err
	}
	return nil
}

type TrTxWitness struct {
	b_hat      *PolyNTTVec
	c_hats     []*PolyNTT
	u_p        []int32
	rpulpproof *rpulpProof
	cmtps      []*Commitment
	elrsSigs   []*elrsSignature
}

func (trTxWitness *TrTxWitness) SerializeSize() uint32 {
	// todo
	return 1
}

func (trTxWitness *TrTxWitness) Serialize() []byte {
	// todo
	return nil
}

func (trTxWitness *TrTxWitness) Deserialize(serializedTxWitness []byte) error {
	// todo
	return nil
}

type TransferTx struct {
	//	Version uint32

	Inputs     []*TrTxInput
	OutputTxos []*TXO
	Fee        uint64

	TxMemo []byte

	TxWitness *TrTxWitness
}

func (trTx *TransferTx) Serialize() ([]byte, error) {
	w := new(bytes.Buffer)

	// write inputs size
	count := uint64(len(trTx.Inputs))
	err := WriteVarInt(w, count)
	if err != nil {
		return nil, err
	}
	// write inputs
	for _, input := range trTx.Inputs {
		err := input.Serialize(w)
		if err != nil {
			return nil, err
		}
	}

	// write outputs size
	count = uint64(len(trTx.OutputTxos))
	err = WriteVarInt(w, count)
	if err != nil {
		return nil, err
	}
	// write outputs
	for _, output := range trTx.OutputTxos {
		err := output.Serialize(w)
		if err != nil {
			return nil, err
		}
	}

	// write txFee
	err = WriteVarInt(w, trTx.Fee)
	if err != nil {
		return nil, err
	}

	// write txMemo size
	count = uint64(len(trTx.TxMemo))
	err = WriteVarInt(w, count)
	if err != nil {
		return nil, err
	}
	// write txMemo
	w.Write(trTx.TxMemo[:])

	// write txWitness?

	return w.Bytes(), nil
}

type DerivedPubKey struct {
	ckem []byte
	t    *PolyNTTVec
}

type Commitment struct {
	b *PolyNTTVec
	c *PolyNTT
}

type rpulpProof struct {
	c_waves []*PolyNTT
	c_hat_g *PolyNTT
	psi     *PolyNTT
	phi     *PolyNTT
	chseed  []byte
	cmt_zs  [][]*PolyNTTVec
	zs      []*PolyNTTVec
}

type elrsSignature struct {
	chseed []byte
	z_as   [][]*PolyNTTVec
	z_cs   [][]*PolyNTTVec
	keyImg *PolyNTTVec
}

func (pp *PublicParameter) GetMasterPublicKeyByteLen() int {
	return 1 // todo
}

func (pp *PublicParameter) GetTxoByteLen() int {
	return 1 // todo
}

/*type ValueCommitment struct {

}

type ValueCiphertext struct {

}*/

type TxInputDesc struct {
	txoList []*TXO
	sidx    int
	mpk     *MasterPublicKey
	msvk    *MasterSecretViewKey
	mssk    *MasterSecretSignKey
	value   uint64
}

func NewTxInputDesc(txpList []*TXO, sidx int, mpk *MasterPublicKey, msvk *MasterSecretViewKey, mssk *MasterSecretSignKey, value uint64) *TxInputDesc {
	return &TxInputDesc{
		txpList,
		sidx,
		mpk,
		msvk,
		mssk,
		value,
	}
}

type TxOutputDesc struct {
	mpk   *MasterPublicKey
	value uint64
}

func NewTxOutputDesc(mpk *MasterPublicKey, value uint64) *TxOutputDesc {
	return &TxOutputDesc{
		mpk,
		value,
	}
}

type TXO struct {
	dpk *DerivedPubKey
	cmt *Commitment
	vc  []byte
}

func (txo *TXO) SerializeSize() uint32 {
	// todo
	return 1
}

func (txo *TXO) Deserialize(serializedTxo []byte) error {
	// todo
	return nil
}

func (txo *TXO) Serialize(w io.Writer) error {
	// write dpk.ckem
	count := len(txo.dpk.ckem)
	err := WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	_, err = w.Write(txo.dpk.ckem)
	if err != nil {
		return err
	}

	// write dpk.t
	count = len(txo.dpk.t.polyNTTs)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		cnt := len(txo.dpk.t.polyNTTs[i].coeffs)
		err = WriteVarInt(w, uint64(cnt))
		if err != nil {
			return err
		}
		for j := 0; j < cnt; j++ {
			err = WriteVarInt(w, uint64(txo.dpk.t.polyNTTs[i].coeffs[j]))
			if err != nil {
				return err
			}
		}
	}

	//write cmt.b
	count = len(txo.cmt.b.polyNTTs)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		cnt := len(txo.cmt.b.polyNTTs[i].coeffs)
		err = WriteVarInt(w, uint64(cnt))
		if err != nil {
			return err
		}
		for j := 0; j < cnt; j++ {
			err = WriteVarInt(w, uint64(txo.cmt.b.polyNTTs[i].coeffs[j]))
			if err != nil {
				return err
			}
		}
	}

	// write cmt.c
	count = len(txo.cmt.c.coeffs)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		err = WriteVarInt(w, uint64(txo.cmt.c.coeffs[i]))
		if err != nil {
			return err
		}
	}

	// write vc
	count = len(txo.vc)
	err = WriteVarInt(w, uint64(count))
	if err != nil {
		return err
	}
	_, err = w.Write(txo.vc[:])
	if err != nil {
		return err
	}
	return nil
}

//	public fun	begin
func Setup() (pp *PublicParameter) {
	// todo
	return nil
}

func (pp *PublicParameter) MasterKeyGen(seed []byte) (retSeed []byte, mpk *MasterPublicKey, msvk *MasterSecretViewKey, mssk *MasterSecretSignKey, err error) {
	/*	mpk := MasterPublicKey{}
		msvk := MasterSecretViewKey{}
		mssk := MasterSecretSignKey{}

		return &mpk, &msvk, &mssk, nil*/

	//	kappa := []byte
	var s *PolyNTTVec
	if seed != nil {
		//	todo:
		//	todo: check the validity of seed
		randomnessA, err := pp.expandRandomnessA(seed)
		if err != nil {
			return seed, nil, nil, nil, err
		}
		s = pp.NTTVec(randomnessA)
	} else {
		randomnessA, err := pp.sampleRandomnessA()
		if err != nil {
			return seed, nil, nil, nil, err
		}
		s = pp.NTTVec(randomnessA)
	}
	//len(s.polys) != pp.paramLa

	t := pp.PolyNTTMatrixMulVector(pp.paramMatrixA, s, pp.paramKa, pp.paramLa)

	rstmpk := &MasterPublicKey{
		nil, // todo
		t,
	}

	rstmsvk := &MasterSecretViewKey{
		skkem: nil,
	}

	rstmssk := &MasterSecretSignKey{
		s: s,
	}

	return seed, rstmpk, rstmsvk, rstmssk, nil
}

func (pp *PublicParameter) collectBytesForCoinbase1(vin uint64, cmts []*Commitment, ws []*PolyNTTVec, deltas []*PolyNTT) []byte {
	tmp := make([]byte, pp.paramD*4+(pp.paramKc+1)*pp.paramD*4+(pp.paramKc+1)*pp.paramD*4)
	appendPolyNTTToBytes := func(a *PolyNTT) {
		for k := 0; k < pp.paramD; k++ {
			tmp = append(tmp, byte(a.coeffs[k]>>0))
			tmp = append(tmp, byte(a.coeffs[k]>>8))
			tmp = append(tmp, byte(a.coeffs[k]>>16))
			tmp = append(tmp, byte(a.coeffs[k]>>24))
		}
	}

	mbin := intToBinary(vin, pp.paramD)
	m := &PolyNTT{mbin}
	appendPolyNTTToBytes(m)

	for i := 0; i < len(cmts[0].b.polyNTTs); i++ {
		appendPolyNTTToBytes(cmts[0].b.polyNTTs[i])
	}
	appendPolyNTTToBytes(cmts[0].c)

	for i := 0; i < pp.paramK; i++ {
		for j := 0; j < pp.paramKc; j++ {
			appendPolyNTTToBytes(ws[i].polyNTTs[j])
		}
		appendPolyNTTToBytes(deltas[i])
	}
	return tmp
}

func (pp *PublicParameter) collectBytesForCoinbase2(b_hat *PolyNTTVec, c_hats []*PolyNTT) []byte {
	res := make([]byte, pp.paramKc*pp.paramD*4+pp.paramD*4*len(c_hats))
	appendPolyNTTToBytes := func(a *PolyNTT) {
		for k := 0; k < pp.paramD; k++ {
			res = append(res, byte(a.coeffs[k]>>0))
			res = append(res, byte(a.coeffs[k]>>8))
			res = append(res, byte(a.coeffs[k]>>16))
			res = append(res, byte(a.coeffs[k]>>24))
		}
	}
	for i := 0; i < pp.paramKc; i++ {
		appendPolyNTTToBytes(b_hat.polyNTTs[i])
	}
	for i := 0; i < len(c_hats); i++ { //TODO check the length of c_hats
		appendPolyNTTToBytes(c_hats[i])
	}
	return res
}
func (pp *PublicParameter) CoinbaseTxGen(vin uint64, txOutputDescs []*TxOutputDesc) (cbTx *CoinbaseTx, err error) {
	V := uint64(1)<<pp.paramN - 1

	if vin > V {
		return nil, errors.New("vin is not in [0, V]") // todo: more accurate info
	}

	if len(txOutputDescs) == 0 || len(txOutputDescs) > pp.paramJ {
		return nil, errors.New("the number of outputs is not in [1, I_max]") // todo: more accurate info
	}

	J := len(txOutputDescs)

	retcbTx := &CoinbaseTx{}
	//	retcbTx.Version = 0 // todo: how to set and how to use the version? The bpf just care the content of cbTx?
	retcbTx.Vin = vin
	retcbTx.OutputTxos = make([]*TXO, J)

	cmts := make([]*Commitment, J)
	cmt_rs := make([]*PolyNTTVec, J)

	vout := uint64(0)
	for j, txOutputDesc := range txOutputDescs {
		if txOutputDesc.value > V {
			return nil, errors.New("value is not in [0, V]") // todo: more accurate info, including the i
		}
		vout += txOutputDesc.value
		if vout > V {
			return nil, errors.New("the output value is not in [0, V]") // todo: more accurate info, including the i
		}

		retcbTx.OutputTxos[j], cmt_rs[j], err = pp.txoGen(txOutputDesc.mpk, txOutputDesc.value)
		if err != nil {
			return nil, err
		}
		cmts[j] = retcbTx.OutputTxos[j].cmt
	}
	if vout > vin {
		return nil, errors.New("the output value exceeds the input value") // todo: more accurate info
	}

	if J == 1 {
		ys := make([]*PolyNTTVec, pp.paramK)
		ws := make([]*PolyNTTVec, pp.paramK)
		deltas := make([]*PolyNTT, pp.paramK)
		zs := make([]*PolyNTTVec, pp.paramK)

	cbTxGenJ1Restart:
		for t := 0; t < pp.paramK; t++ {
			maskC, err := pp.sampleMaskC()
			if err != nil {
				return nil, err
			}
			ys[t] = pp.NTTVec(maskC)

			ws[t] = pp.PolyNTTMatrixMulVector(pp.paramMatrixB, ys[t], pp.paramKc, pp.paramLc)
			deltas[t] = pp.PolyNTTVecInnerProduct(pp.paramMatrixC[0], ys[t], pp.paramLc)
		}

		chseed, err := H(pp.collectBytesForCoinbase1(vin, cmts, ws, deltas))
		if err != nil {
			return nil, err
		}
		chtmp, err := pp.expandChallenge(chseed)
		if err != nil {
			return nil, err
		}
		ch := pp.NTT(chtmp)

		for t := 0; t < pp.paramK; t++ {
			zs[t] = pp.PolyNTTVecAdd(
				ys[t],
				pp.PolyNTTVecScaleMul(pp.sigmaPowerPolyNTT(ch, t), cmt_rs[0], pp.paramLc),
				pp.paramLc)

			if pp.NTTInvVec(zs[t]).infNorm() > pp.paramEtaC-pp.paramBetaC {
				goto cbTxGenJ1Restart
			}
		}

		retcbTx.TxWitness = &CbTxWitness{
			rpulpproof: &rpulpProof{
				chseed: chseed,
				zs:     zs,
			},
		}
	} else {
		//	J >= 2
		n := J
		n2 := n + 2

		c_hats := make([]*PolyNTT, n2)

		msg_hats := make([][]int32, n2)

		u_hats := make([][]int32, 3)
		u_hats[0] = intToBinary(vin, pp.paramD)

		for j := 0; j < J; j++ {
			msg_hats[j] = intToBinary(txOutputDescs[j].value, pp.paramD)
		}

		u := intToBinary(vin, pp.paramD)

		//	f is the carry vector, such that, u = m_0 + m_1 + ... + m_{J-1}
		//	f[0] = 0, and for i=1 to d-1,
		//	m_0[i-1]+ ... + m_{J-1}[i-1] + f[i-1] = u[i-1] + 2 f[i],
		//	m_0[i-1]+ ... + m_{J-1}[i-1] + f[i-1] = u[i-1]
		f := make([]int32, pp.paramD)
		f[0] = 0
		for i := 1; i < pp.paramD; i++ {
			tmp := int32(0)
			for j := 0; j < J; j++ {
				tmp = tmp + msg_hats[j][i-1]
			}
			f[i] = (tmp + f[i-1] - u[i-1]) >> 1
		}
		msg_hats[J] = f

	cbTxGenJ2Restart:
		e := make([]int32, pp.paramD) //	todo_DONE: sample e from ([-eta_f, eta_f])^d
		//TODO whether the function meet the need?
		e, err := pp.sampleUniformWithinEtaF()
		if err != nil {
			return nil, err
		}
		msg_hats[J+1] = e

		_, randomnessC, err := pp.sampleRandomnessC()
		if err != nil {
			return nil, err
		}
		r_hat := pp.NTTVec(randomnessC)

		b_hat := pp.PolyNTTMatrixMulVector(pp.paramMatrixB, r_hat, pp.paramKc, pp.paramLc)

		for i := 0; i < n2; i++ { // n2 = J+2
			c_hats[i] = pp.PolyNTTAdd(
				pp.PolyNTTVecInnerProduct(pp.paramMatrixC[i+1], r_hat, pp.paramLc),
				&PolyNTT{msg_hats[i]})
		}

		//	todo: check the scope of u_p in theory
		u_p := make([]int32, pp.paramD) // todo: make sure that (eta_f, d) will not make the value of u_p[i] over int32
		u_p_tmp := make([]int64, pp.paramD)

		seed_binM, err := H(pp.collectBytesForCoinbase2(b_hat, c_hats)) // todo_DONE: compute the seed using hash function on (b_hat, c_hats).
		if err != nil {
			return nil, err
		}
		binM, err := expandBinaryMatrix(seed_binM, pp.paramD, pp.paramD)
		if err != nil {
			return nil, err
		}
		// todo: check B f + e
		for i := 0; i < pp.paramD; i++ {
			u_p_tmp[i] = 0
			for j := 0; j < pp.paramD; j++ {
				u_p_tmp[i] = u_p_tmp[i] + int64(binM[i][j])*int64(f[j]) + int64(e[j])
			}

			infNorm := u_p_tmp[i]
			if infNorm < 0 {
				infNorm = -infNorm
			}
			if infNorm > int64(pp.paramEtaF-int32(J-1)) {
				goto cbTxGenJ2Restart
			}

			u_p[i] = pp.reduce(u_p_tmp[i])
		}

		u_hats[1] = make([]int32, pp.paramD) // todo: all zero
		u_hats[2] = u_p

		n1 := n
		rprlppi, pi_err := pp.rpulpProve(cmts, cmt_rs, n, b_hat, r_hat, c_hats, msg_hats, n2, n1, RpUlpTypeCbTx2, binM, 0, J, 3, u_hats)

		if pi_err != nil {
			return nil, pi_err
		}

		retcbTx.TxWitness = &CbTxWitness{
			b_hat:      b_hat,
			c_hats:     c_hats,
			u_p:        u_p,
			rpulpproof: rprlppi,
		}
	}

	return retcbTx, nil
}

func (pp *PublicParameter) CoinbaseTxVerify(cbTx *CoinbaseTx) bool {
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

	// todo: check no repeated dpk in cbTx.OutputTxos
	// todo: check cbTx.OutputTxos[j].cmt is well-formed

	if J == 1 {
		//if cbTx.TxWitness.b_hat != nil || cbTx.TxWitness.b_hat != nil || cbTx.TxWitness.u_p != nil {
		//	return false
		//}
		//if cbTx.TxWitness.rpulpproof == nil {
		//	return false
		//}
		//
		//if cbTx.TxWitness.rpulpproof.c_waves != nil || cbTx.TxWitness.rpulpproof.c_hat_g != nil ||
		//	cbTx.TxWitness.rpulpproof.psi != nil || cbTx.TxWitness.rpulpproof.psi != nil ||
		//	cbTx.TxWitness.rpulpproof.cmt_zs != nil {
		//	return false
		//}
		if cbTx.TxWitness.rpulpproof.chseed == nil || cbTx.TxWitness.rpulpproof.zs == nil {
			return false
		}
		// todo check the well-form of ch

		// check the well-formof zs
		if len(cbTx.TxWitness.rpulpproof.zs) != pp.paramK {
			return false
		}
		// infNorm of z^t
		for t := 0; t < pp.paramK; t++ {
			if pp.NTTInvVec(cbTx.TxWitness.rpulpproof.zs[t]).infNorm() > pp.paramEtaC-pp.paramBetaC {
				return false
			}
		}

		ws := make([]*PolyNTTVec, pp.paramK)
		deltas := make([]*PolyNTT, pp.paramK)

		chtmp, err := pp.expandChallenge(cbTx.TxWitness.rpulpproof.chseed)
		if err != nil {
			return false
		}
		ch := pp.NTT(chtmp)
		msg := intToBinary(cbTx.Vin, pp.paramD)
		for t := 0; t < pp.paramK; t++ {
			sigma_t_ch := pp.sigmaPowerPolyNTT(ch, t)

			ws[t] = pp.PolyNTTVecSub(
				pp.PolyNTTMatrixMulVector(pp.paramMatrixB, cbTx.TxWitness.rpulpproof.zs[t], pp.paramKc, pp.paramLc),
				pp.PolyNTTVecScaleMul(sigma_t_ch, cbTx.OutputTxos[0].cmt.b, pp.paramLc),
				pp.paramLc)
			deltas[t] = pp.PolyNTTSub(
				pp.PolyNTTVecInnerProduct(pp.paramMatrixC[0], cbTx.TxWitness.rpulpproof.zs[t], pp.paramLc),
				pp.PolyNTTMul(
					sigma_t_ch,
					pp.PolyNTTSub(cbTx.OutputTxos[0].cmt.c, &PolyNTT{msg})))
		}

		seed_ch, err := H(pp.collectBytesForCoinbase1(cbTx.Vin, []*Commitment{cbTx.OutputTxos[0].cmt}, ws, deltas))
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
		infNorm := int32(0)
		if len(cbTx.TxWitness.u_p) != pp.paramD {
			return false
		}
		for i := 0; i < pp.paramD; i++ {
			infNorm = cbTx.TxWitness.u_p[i]
			if infNorm < 0 {
				infNorm = -infNorm
			}

			if infNorm >= (pp.paramEtaF - int32(J-1)) { // todo: q/12 or eta_f - (J-1)
				return false
			}
		}

		seed_binM, err := H(pp.collectBytesForCoinbase2(cbTx.TxWitness.b_hat, cbTx.TxWitness.c_hats)) // todo_DONE: compute the seed using hash function on (b_hat, c_hats).
		if err != nil {
			return false
		}
		binM, err := expandBinaryMatrix(seed_binM, pp.paramD, pp.paramD)
		if err != nil {
			return false
		}

		u_hats := make([][]int32, 3)
		u_hats[0] = intToBinary(cbTx.Vin, pp.paramD)
		u_hats[1] = make([]int32, pp.paramD) // todo: all zero
		u_hats[2] = cbTx.TxWitness.u_p

		cmts := make([]*Commitment, n)
		for i := 0; i < n; i++ {
			cmts[i] = cbTx.OutputTxos[i].cmt
		}

		n1 := n
		return pp.rpulpVerify(cmts, n, cbTx.TxWitness.b_hat, cbTx.TxWitness.c_hats, n2, n1, RpUlpTypeCbTx2, binM, 0, J, 3, u_hats, cbTx.TxWitness.rpulpproof)
	}

	return true
}

func (pp *PublicParameter) TxoCoinReceive(txo *TXO, mpk *MasterPublicKey, msvk *MasterSecretViewKey) (valid bool, coinvale uint64, err error) {
	if txo == nil || mpk == nil || msvk == nil {
		return false, 0, errors.New("nil pointer")
	}

	// todo: check the well-formness of dpk
	// (C, t)

	// todo_DONE: decaps and obtain kappa
	kappa := msvk.skkem.CryptoKemDec(txo.dpk.ckem)
	sptmp, err := pp.expandRandomnessA(kappa) // TODO_DONE handle the err
	if err != nil {
		return false, 0, err
	}
	s_p := pp.NTTVec(sptmp)
	t_hat_p := pp.PolyNTTVecAdd(
		mpk.t,
		pp.PolyNTTMatrixMulVector(pp.paramMatrixA, s_p, pp.paramKa, pp.paramLa),
		pp.paramKa)

	if pp.PolyNTTVecEqualCheck(txo.dpk.t, t_hat_p) != true {
		return false, 0, errors.New("not Equal")
	}

	v := uint64(0) // todo: recover value from txo.vc
	// todo: check value

	m := intToBinary(v, pp.paramD)
	cmtrtmp, err := pp.expandRandomnessC(kappa) // TODO_DONE handle the err
	if err != nil {
		return false, 0, err
	}
	cmt_r := pp.NTTVec(cmtrtmp)
	cmt := &Commitment{}
	cmt.b = pp.PolyNTTMatrixMulVector(pp.paramMatrixB, cmt_r, pp.paramKc, pp.paramLc)
	cmt.c = pp.PolyNTTAdd(
		pp.PolyNTTVecInnerProduct(pp.paramMatrixC[0], cmt_r, pp.paramLc),
		&PolyNTT{m})

	if pp.PolyNTTVecEqualCheck(cmt.b, txo.cmt.b) != true {
		return false, 0, errors.New("not Equal")
	}

	if pp.PolyNTTEqualCheck(cmt.c, txo.cmt.c) != true {
		return false, 0, errors.New("not Equal")
	}

	return true, v, nil
}

func (pp *PublicParameter) collectBytesForTransfer(b_hat *PolyNTTVec, c_hats []*PolyNTT) []byte {
	res := make([]byte, pp.paramKc*pp.paramD*4+pp.paramD*4*len(c_hats))
	appendPolyNTTToBytes := func(a *PolyNTT) {
		for k := 0; k < pp.paramD; k++ {
			res = append(res, byte(a.coeffs[k]>>0))
			res = append(res, byte(a.coeffs[k]>>8))
			res = append(res, byte(a.coeffs[k]>>16))
			res = append(res, byte(a.coeffs[k]>>24))
		}
	}
	for i := 0; i < pp.paramKc; i++ {
		appendPolyNTTToBytes(b_hat.polyNTTs[i])
	}
	for i := 0; i < len(c_hats); i++ { //TODO check the length of c_hats
		appendPolyNTTToBytes(c_hats[i])
	}
	return res
}

func (pp *PublicParameter) TransferTxGen(inputDescs []*TxInputDesc, outputDescs []*TxOutputDesc, fee uint64, txMemo []byte) (trTx *TransferTx, err error) {
	//	check the well-formness of the inputs and outputs
	if len(inputDescs) == 0 || len(outputDescs) == 0 {
		return nil, err // todo: err info
	}

	if len(inputDescs) > pp.paramI {
		return nil, errors.New("too many inputs") //Todo: may define a new error type?
	}
	if len(outputDescs) > pp.paramJ {
		return nil, errors.New("too many outputs") ////Todo: may define a new error type?
	}

	V := uint64(1)<<pp.paramD - 1

	if fee > V {
		return nil, err // todo: err info
	}

	//	check on the outputDesc is simple, so check it first
	outputTotal := fee
	for _, outputDescItem := range outputDescs {
		if outputDescItem.value > V {
			return nil, err // todo: err info
		}
		outputTotal = outputTotal + outputDescItem.value
		if outputTotal > V {
			return nil, err // todo: err info
		}

		if outputDescItem.mpk == nil {
			return nil, err // todo: err info
		}
		if outputDescItem.mpk.WellformCheck(pp) == false {
			return nil, err // todo: err info
		}
	}

	inputTotal := uint64(0)
	for _, inputDescItem := range inputDescs {
		if inputDescItem.value > V {
			return nil, err // todo: err info
		}
		inputTotal = inputTotal + inputDescItem.value
		if inputTotal > V {
			return nil, err // todo: err info
		}

		if len(inputDescItem.txoList) == 0 {
			return nil, err // todo: err info
		}
		if inputDescItem.sidx < 0 || inputDescItem.sidx >= len(inputDescItem.txoList) {
			return nil, err // todo: err info
		}
		if inputDescItem.mpk == nil || inputDescItem.msvk == nil || inputDescItem.mssk == nil {
			return nil, err // todo: err info
		}

		if inputDescItem.mssk.WellformCheck(pp) == false {
			return nil, err // todo: err info
		}

		b, v, err := pp.TxoCoinReceive(inputDescItem.txoList[inputDescItem.sidx], inputDescItem.mpk, inputDescItem.msvk)
		if b == false || v != inputDescItem.value || err != nil {
			return nil, err // todo: err info
		}

		//	check no repeated dpk in inputDescItem.txoList
		var mapDpk map[*DerivedPubKey]bool
		mapDpk = make(map[*DerivedPubKey]bool)
		for _, txo := range inputDescItem.txoList {
			_, ok := mapDpk[txo.dpk]
			if ok {
				return nil, err // todo: err info
			}
			mapDpk[txo.dpk] = true
		}
		// todo
		//	check inputDescItem[i].txoList[inputDescItem[i].sidx].dpk \neq inputDescItem[j].txoList[inputDescItem[j].sidx].dpk
		//	check (inputDescItem[i].txoList == inputDescItem[j].txoList) or (inputDescItem[i].txoList \cap inputDescItem[j].txoList = \emptyset)
	}

	if outputTotal != inputTotal {
		return nil, err // todo: err info
	}

	I := len(inputDescs)
	J := len(outputDescs)
	n := I + J
	n2 := I + J + 2
	if I > 1 {
		n2 = I + J + 4
	}

	msg_hats := make([][]int32, n2)

	cmts := make([]*Commitment, n)
	cmt_rs := make([]*PolyNTTVec, n)

	rettrTx := &TransferTx{}
	rettrTx.Inputs = make([]*TrTxInput, I)
	rettrTx.OutputTxos = make([]*TXO, J)
	rettrTx.Fee = fee
	rettrTx.TxMemo = txMemo

	for j := 0; j < J; j++ {
		rettrTx.OutputTxos[j], cmt_rs[I+j], err = pp.txoGen(outputDescs[j].mpk, outputDescs[j].value)
		if err != nil {
			return nil, err // todo
		}

		cmts[I+j] = rettrTx.OutputTxos[j].cmt
		msg_hats[I+j] = intToBinary(outputDescs[j].value, pp.paramD)
	}

	for i := 0; i < I; i++ {
		rettrTx.Inputs[i].TxoList = inputDescs[i].txoList
		rettrTx.Inputs[i].SerialNumber, err = pp.TxoSerialNumberGen(inputDescs[i].txoList[inputDescs[i].sidx], inputDescs[i].mpk, inputDescs[i].msvk, inputDescs[i].mssk)
		if err != nil {
			return nil, err
		}
	}

	msgTrTxCon, err := rettrTx.Serialize()
	if err != nil {
		return nil, err
	}
	msgTrTxConHash, err := H(msgTrTxCon)
	if err != nil {
		return nil, err
	}

	elrsSigs := make([]*elrsSignature, I)
	cmtps := make([]*Commitment, I)

	for i := 0; i < I; i++ {
		msg_hats[i] = intToBinary(inputDescs[i].value, pp.paramD)

		//	dpk = inputDescs[i].txoList[inputDescs[i].sidx].dpk = (C, t)
		// todo
		kappa := []byte{}

		satmp, err := pp.expandRandomnessA(kappa)
		if err != nil {
			return nil, err
		}
		s_a := pp.PolyNTTVecAdd(
			inputDescs[i].mssk.s,
			pp.NTTVec(satmp),
			pp.paramKa)

		_, randomnessC, err := pp.sampleRandomnessC()
		if err != nil {
			return nil, err
		}
		cmt_rs[i] = pp.NTTVec(randomnessC)
		cmtps[i] = &Commitment{}
		cmtps[i].b = pp.PolyNTTMatrixMulVector(pp.paramMatrixB, cmt_rs[i], pp.paramKc, pp.paramLc)
		cmtps[i].c = pp.PolyNTTAdd(
			pp.PolyNTTVecInnerProduct(pp.paramMatrixC[0], cmt_rs[i], pp.paramLc),
			&PolyNTT{msg_hats[i]})

		cmts[i] = cmtps[i]
		sctmp, err := pp.expandRandomnessC(kappa)
		if err != nil {
			return nil, err
		}
		s_c := pp.PolyNTTVecSub(
			pp.NTTVec(sctmp),
			cmt_rs[i],
			pp.paramLc)

		t_c_p := cmtps[i].toPolyNTTVec()

		ringSize := len(inputDescs[i].txoList)
		t_as := make([]*PolyNTTVec, ringSize)
		t_cs := make([]*PolyNTTVec, ringSize)
		for j := 0; j < ringSize; j++ {
			t_as[j] = inputDescs[i].txoList[j].dpk.t

			if len(inputDescs[i].txoList[j].cmt.b.polyNTTs) != pp.paramKc {
				return nil, err // todo
			}
			t_cs[j] = inputDescs[i].txoList[j].cmt.toPolyNTTVec()
			t_cs[j] = pp.PolyNTTVecSub(t_cs[j], t_c_p, pp.paramKc+1)
		}

		elrsSigs[i], err = pp.elrsSign(t_as, t_cs, msgTrTxConHash, inputDescs[i].sidx, s_a, s_c)
		if err != nil {
			return nil, err // todo
		}
	}

	//	u
	u := intToBinary(fee, pp.paramD)

	if I == 1 {
		c_hats := make([]*PolyNTT, n2) //	n2 = n+2

		//	f is the carry vector, such that, m_1 = m_2+ ... + m_n + u
		//	f[0] = 0, and for i=1 to d-1,
		//	m_0[i-1] + 2 f[i] = m_1[i-1] + .. + m_{n-1}[i-1] + u[i-1] + f[i-1],
		//	m_0[d-1] 		  = m_1[d-1] + .. + m_{n-1}[d-1] + f[d-1],
		f := make([]int32, pp.paramD)
		f[0] = 0
		for i := 1; i < pp.paramD; i++ {
			tmp := int32(0)
			for j := 1; j < n; j++ {
				tmp = tmp + msg_hats[j][i-1]
			}
			f[i] = (tmp + u[i-1] + f[i-1] - msg_hats[0][i-1]) >> 1
		}
		msg_hats[n] = f

	trTxGenI1Restart:
		e, err := pp.sampleUniformWithinEtaF()
		if err != nil {
			return nil, err
		}
		msg_hats[n+1] = e

		_, randomnessC, err := pp.sampleRandomnessC()
		if err != nil {
			return nil, err
		}
		r_hat := pp.NTTVec(randomnessC)
		b_hat := pp.PolyNTTMatrixMulVector(pp.paramMatrixB, r_hat, pp.paramKc, pp.paramLc)
		for i := 0; i < n2; i++ { // n2 = I+J+4 = n+4
			c_hats[i] = pp.PolyNTTAdd(
				pp.PolyNTTVecInnerProduct(pp.paramMatrixC[i+1], r_hat, pp.paramLc),
				&PolyNTT{msg_hats[i]})
		}

		// todo: check the scope of u_p in theory
		u_p := make([]int32, pp.paramD)
		u_p_temp := make([]int64, pp.paramD)                           // todo: make sure that (eta_f, d) will not make the value of u_p[i] over int32
		seed_binM, err := H(pp.collectBytesForTransfer(b_hat, c_hats)) // todo: compute the seed using hash function on (b_hat, c_hats).
		if err != nil {
			return nil, err
		}
		binM, err := expandBinaryMatrix(seed_binM, pp.paramD, pp.paramD)
		if err != nil {
			return nil, err
		}
		// todo: check B f + e
		for i := 0; i < pp.paramD; i++ {
			u_p_temp[i] = 0
			for j := 0; j < pp.paramD; j++ {
				u_p_temp[i] = u_p_temp[i] + int64(binM[i][j])*int64(f[j]) + int64(e[j])
			}

			infNorm := u_p_temp[i]
			if infNorm < 0 {
				infNorm = -infNorm
			}

			if infNorm > int64(pp.paramEtaF-int32(J)) {
				goto trTxGenI1Restart
			}

			u_p[i] = pp.reduce(u_p_temp[i])
		}

		u_hats := make([][]int32, 3)
		u_hats[0] = u
		u_hats[1] = make([]int32, pp.paramD) // todo: all zero
		u_hats[2] = u_p

		n1 := n
		rprlppi, pi_err := pp.rpulpProve(cmts, cmt_rs, n, b_hat, r_hat, c_hats, msg_hats, n2, n1, RpUlpTypeTrTx2, binM, I, J, 5, u_hats)

		if pi_err != nil {
			return nil, pi_err
		}

		trTx.TxWitness = &TrTxWitness{
			b_hat:      b_hat,
			c_hats:     c_hats,
			u_p:        u_p,
			rpulpproof: rprlppi,
			cmtps:      cmtps,
			elrsSigs:   elrsSigs,
		}

	} else {

		c_hats := make([]*PolyNTT, n2) //	n2 = n+4

		msg_hats[n] = intToBinary(inputTotal, pp.paramD) //	v_in

		//	f1 is the carry vector, such that, m_0 + m_1+ ... + m_{I-1} = m_{n}
		//	f1[0] = 0, and for i=1 to d-1,
		//	m_0[i-1] + .. + m_{I-1}[i-1] + f1[i-1] = m_n[i-1] + 2 f[i] ,
		//	m_0[d-1] + .. + m_{I-1}[d-1] + f1[d-1] = m_n[d-1] ,
		f1 := make([]int32, pp.paramD)
		f1[0] = 0
		for i := 1; i < pp.paramD; i++ {
			tmp := int32(0)
			for j := 0; j < I; j++ {
				tmp = tmp + msg_hats[j][i-1]
			}
			f1[i] = (tmp + f1[i-1] - msg_hats[n][i-1]) >> 1
		}
		msg_hats[n+1] = f1

		//	f2 is the carry vector, such that, m_I + m_{I+1}+ ... + m_{(I+J)-1} + u = m_{n}
		//	f2[0] = 0, and for i=1 to d-1,
		//	m_I[i-1] + .. + m_{I+J-1}[i-1] + u[i-1] + f2[i-1] = m_n[i-1] + 2 f[i] ,
		//	m_I[d-1] + .. + m_{I+J-1}[d-1] + u[d-1] + f2[d-1] = m_n[d-1] ,
		f2 := make([]int32, pp.paramD)
		f2[0] = 0
		for i := 1; i < pp.paramD; i++ {
			tmp := int32(0)
			for j := 0; j < I; j++ {
				tmp = tmp + msg_hats[I+j][i-1]
			}
			f2[i] = (tmp + u[i-1] + f2[i-1] - msg_hats[n][i-1]) >> 1
		}
		msg_hats[n+2] = f2

	trTxGenI2Restart:
		e, err := pp.sampleUniformWithinEtaF()
		if err != nil {
			return nil, err
		}
		msg_hats[n+3] = e

		_, randomnessC, err := pp.sampleRandomnessC()
		if err != nil {
			return nil, err
		}
		r_hat := pp.NTTVec(randomnessC)

		b_hat := pp.PolyNTTMatrixMulVector(pp.paramMatrixB, r_hat, pp.paramKc, pp.paramLc)

		for i := 0; i < n2; i++ { // n2 = I+J+4 = n+4
			c_hats[i] = pp.PolyNTTAdd(
				pp.PolyNTTVecInnerProduct(pp.paramMatrixC[i+1], r_hat, pp.paramLc),
				&PolyNTT{msg_hats[i]})
		}

		// todo: check the scope of u_p in theory
		u_p := make([]int32, pp.paramD)
		u_p_temp := make([]int64, pp.paramD)                           // todo: make sure that (eta_f, d) will not make the value of u_p[i] over int32
		seed_binM, err := H(pp.collectBytesForTransfer(b_hat, c_hats)) // todo: compute the seed using hash function on (b_hat, c_hats).
		if err != nil {
			return nil, err
		}
		binM, err := expandBinaryMatrix(seed_binM, pp.paramD, 2*pp.paramD)
		if err != nil {
			return nil, err
		}
		// todo: check B (f_1 || f_2) + e
		betaF := I
		if J+1 > betaF {
			betaF = J + 1
		}
		betaF = betaF - 1

		for i := 0; i < pp.paramD; i++ {
			u_p_temp[i] = 0
			for j := 0; j < pp.paramD; j++ {
				u_p_temp[i] = u_p_temp[i] + int64(binM[i][j])*int64(f1[j]) + int64(binM[i][pp.paramD+j])*int64(f2[j]) + int64(e[j])
			}

			infNorm := u_p_temp[i]
			if infNorm < 0 {
				infNorm = -infNorm
			}

			if infNorm > int64(pp.paramEtaF-int32(betaF)) {
				goto trTxGenI2Restart
			}

			u_p[i] = pp.reduce(u_p_temp[i])
		}

		u_hats := make([][]int32, 5)
		u_hats[0] = make([]int32, pp.paramD) // todo: all zero
		u_hats[1] = u                        // todo: -u
		u_hats[2] = make([]int32, pp.paramD) // todo: all zero
		u_hats[3] = make([]int32, pp.paramD) // todo: all zero
		u_hats[4] = u_p

		n1 := n + 1
		rprlppi, pi_err := pp.rpulpProve(cmts, cmt_rs, n, b_hat, r_hat, c_hats, msg_hats, n2, n1, RpUlpTypeTrTx2, binM, I, J, 5, u_hats)

		if pi_err != nil {
			return nil, pi_err
		}

		rettrTx.TxWitness = &TrTxWitness{
			b_hat:      b_hat,
			c_hats:     c_hats,
			u_p:        u_p,
			rpulpproof: rprlppi,
			cmtps:      cmtps,
			elrsSigs:   elrsSigs,
		}
	}

	return rettrTx, err
}

func (pp *PublicParameter) TransferTxVerify(trTx *TransferTx) bool {
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

	for i := 0; i < I; i++ {
		input := trTx.Inputs[i]
		if input.TxoList == nil || input.SerialNumber == nil {
			return false
		}
		// todo: check whether there exists repeated dpk in trTx.Inputs[i]

		// todo: check whether there exists two txoList such that they have common Txos but are different

		// todo: check whether theres exits repeated serialNumber
	}

	for j := 0; j < J; j++ {
		//	todo: check the well-form of outputTxos

		// todo: check whether there exits repeated dpk in the outputTxos
	}

	//	todo: check the well-form of TxWitness

	//	check the ring signatures
	msgTrTxCon, err := trTx.Serialize()
	if err != nil {
		return false
	}
	msgTrTxConHash, err := H(msgTrTxCon)
	if err != nil {
		return false
	}
	for i := 0; i < I; i++ {
		//	check the validity of sigma_{lrs,i}
		sn, err := pp.keyImgToSerialNumber(trTx.TxWitness.elrsSigs[i].keyImg)
		if err != nil || bytes.Compare(sn, trTx.Inputs[i].SerialNumber) != 0 {
			return false
		}

		ringSize := len(trTx.Inputs[i].TxoList)
		t_as := make([]*PolyNTTVec, ringSize)
		t_cs := make([]*PolyNTTVec, ringSize)

		t_c_p := trTx.TxWitness.cmtps[i].toPolyNTTVec()
		for j := 0; j < ringSize; j++ {
			t_as[j] = trTx.Inputs[i].TxoList[j].dpk.t

			t_cs[j] = trTx.Inputs[i].TxoList[j].cmt.toPolyNTTVec()
			t_cs[j] = pp.PolyNTTVecSub(t_cs[j], t_c_p, pp.paramKc+1)
		}
		valid := pp.elrsVerify(t_as, t_cs, msgTrTxConHash, trTx.TxWitness.elrsSigs[i])
		if !valid {
			return false
		}
	}

	// check the balance proof
	n := I + J
	cmts := make([]*Commitment, n)
	for i := 0; i < I; i++ {
		cmts[i] = trTx.TxWitness.cmtps[i]
	}
	for j := 0; j < J; j++ {
		cmts[I+j] = trTx.OutputTxos[j].cmt
	}

	u := intToBinary(trTx.Fee, pp.paramD)

	if I == 1 {
		n2 := n + 2
		n1 := n

		betaF := pp.paramEtaF - int32(J)

		//	todo: consider with TransferTxGen
		for i := 0; i < len(trTx.TxWitness.u_p); i++ {
			infNorm := trTx.TxWitness.u_p[i]
			if infNorm < 0 {
				infNorm = -infNorm
			}
			if infNorm > (pp.paramEtaF - int32(betaF)) {
				return false
			}
		}

		seed_binM, err := H(pp.collectBytesForTransfer(trTx.TxWitness.b_hat, trTx.TxWitness.c_hats)) // todo_DONE: compute the seed using hash function on (b_hat, c_hats).
		if err != nil {
			return false
		}
		binM, err := expandBinaryMatrix(seed_binM, pp.paramD, pp.paramD)
		if err != nil {
			return false
		}

		u_hats := make([][]int32, 3)
		u_hats[0] = u                        //
		u_hats[1] = make([]int32, pp.paramD) // todo: all zero
		u_hats[2] = trTx.TxWitness.u_p

		flag := pp.rpulpVerify(cmts, n, trTx.TxWitness.b_hat, trTx.TxWitness.c_hats, n2, n1, RpUlpTypeTrTx2, binM, I, J, 3, u_hats, trTx.TxWitness.rpulpproof)
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
			if infNorm > (pp.paramEtaF - int32(betaF)) {
				return false
			}
		}

		seed_binM, err := H(pp.collectBytesForTransfer(trTx.TxWitness.b_hat, trTx.TxWitness.c_hats)) // todo_DONE: compute the seed using hash function on (b_hat, c_hats).
		binM, err := expandBinaryMatrix(seed_binM, pp.paramD, 2*pp.paramD)
		if err != nil {
			return false
		}

		u_hats := make([][]int32, 5)
		u_hats[0] = make([]int32, pp.paramD) // todo: all zero
		u_hats[1] = u                        // todo: -u
		u_hats[2] = make([]int32, pp.paramD) // todo: all zero
		u_hats[3] = make([]int32, pp.paramD) // todo: all zero
		u_hats[4] = trTx.TxWitness.u_p

		flag := pp.rpulpVerify(cmts, n, trTx.TxWitness.b_hat, trTx.TxWitness.c_hats, n2, n1, RpUlpTypeTrTx2, binM, I, J, 5, u_hats, trTx.TxWitness.rpulpproof)
		if !flag {
			return false
		}
	}

	return true

}

func (pp *PublicParameter) txoGen(mpk *MasterPublicKey, vin uint64) (txo *TXO, r *PolyNTTVec, err error) {
	//	(C, kappa)
	C, kappa, err := mpk.pkkem.CryptoKemEnc()
	s_prime, err := pp.expandRandomnessA(kappa)
	s_p := pp.NTTVec(s_prime)
	t_prime := pp.PolyNTTMatrixMulVector(pp.paramMatrixA, s_p, pp.paramKa, pp.paramLa)
	t := pp.PolyNTTVecAdd(mpk.t, t_prime, pp.paramKa)
	//	(C, t)
	dpk := &DerivedPubKey{
		ckem: C,
		t:    t,
	}
	// todo : dpk.c
	dpk.t = pp.PolyNTTVecAdd(
		mpk.t,
		pp.PolyNTTMatrixMulVector(pp.paramMatrixA, s_p, pp.paramKa, pp.paramLa),
		pp.paramKa)

	//	cmt
	sctmp, err := pp.expandRandomnessC(kappa) //TODO:handle the err
	if err != nil {
		return nil, nil, err
	}
	cmtr := pp.NTTVec(sctmp)

	mtmp := intToBinary(vin, pp.paramD)
	m := pp.NTT(&Poly{coeffs: mtmp})

	cmt := &Commitment{}
	cmt.b = pp.PolyNTTMatrixMulVector(pp.paramMatrixB, cmtr, pp.paramKc, pp.paramLc)
	cmt.c = pp.PolyNTTAdd(
		pp.PolyNTTVecInnerProduct(pp.paramMatrixC[0], cmtr, pp.paramLc),
		m,
	)

	//	vc
	sk, err := pp.expandRandomBitsV(kappa)
	if err != nil {
		return nil, nil, err
	}
	vc := make([]byte, pp.paramD)
	for i := 0; i < pp.paramD; i++ {
		vc[i] = sk[i] ^ byte(mtmp[i])
	}

	rettxo := &TXO{
		dpk,
		cmt,
		vc,
	}

	return rettxo, cmtr, nil
}

//	todo: serial number is a hash value
/*
As wallet may call this algorithm to generate serial numbers for the coins, this method is set to be public.
*/
func (pp *PublicParameter) TxoSerialNumberGen(txo *TXO, mpk *MasterPublicKey, msvk *MasterSecretViewKey, mssk *MasterSecretSignKey) (sn []byte, err error) {
	if txo == nil || txo.dpk == nil || mpk == nil || msvk == nil || mssk == nil {
		return nil, errors.New("nil pointer")
	}

	dpk := txo.dpk

	// todo: check the well-formness of dpk, mpk, msvk, and mssk

	// todo_DONE: decaps and obtain kappa
	kappa := msvk.skkem.CryptoKemDec(dpk.ckem)
	sptmp, err := pp.expandRandomnessA(kappa) //TODO_DONE:handle the err
	if err != nil {
		return nil, err
	}
	sp := pp.NTTVec(sptmp)
	t_hat_p := pp.PolyNTTVecAdd(
		mpk.t,
		pp.PolyNTTMatrixMulVector(pp.paramMatrixA, sp, pp.paramKa, pp.paramLa),
		pp.paramKa)

	if pp.PolyNTTVecEqualCheck(dpk.t, t_hat_p) != true {
		return nil, errors.New("not equal")
	}

	//keyImgMatrix,err := pp.expandKeyImgMatrix(dpk.t)
	tmp := make([]byte, 0, pp.paramKa*pp.paramD*4)
	for ii := 0; ii < pp.paramKa; ii++ {
		for jj := 0; jj < pp.paramD; jj++ {
			tmp = append(tmp, byte(dpk.t.polyNTTs[ii].coeffs[jj]>>0))
			tmp = append(tmp, byte(dpk.t.polyNTTs[ii].coeffs[jj]>>8))
			tmp = append(tmp, byte(dpk.t.polyNTTs[ii].coeffs[jj]>>16))
			tmp = append(tmp, byte(dpk.t.polyNTTs[ii].coeffs[jj]>>24))
		}
	}
	keyImgMatrix, err := pp.expandKeyImgMatrix(tmp)
	if err != nil {
		// TODO: define Const Error Variable
		return nil, errors.New("not equal")
	}
	s_hat := pp.PolyNTTVecAdd(mssk.s, sp, pp.paramKa)

	keyImg := pp.PolyNTTMatrixMulVector(keyImgMatrix, s_hat, pp.paramMa, pp.paramLa)

	// todo_DONE: serialize keyImg and compute the corresponding hash
	return pp.keyImgToSerialNumber(keyImg)
}

//	todo_DONE: serial number is a hash value
func (pp *PublicParameter) keyImgToSerialNumber(keyImg *PolyNTTVec) (sn []byte, err error) {
	// todo:
	seed := make([]byte, 0, pp.paramKa*pp.paramD*4)
	for i := 0; i < len(keyImg.polyNTTs); i++ {
		for j := 0; j < len(keyImg.polyNTTs[i].coeffs); j++ {
			seed = append(seed, byte(keyImg.polyNTTs[i].coeffs[j]>>0))
			seed = append(seed, byte(keyImg.polyNTTs[i].coeffs[j]>>8))
			seed = append(seed, byte(keyImg.polyNTTs[i].coeffs[j]>>16))
			seed = append(seed, byte(keyImg.polyNTTs[i].coeffs[j]>>24))
		}

	}
	imgM, err := pp.expandKeyImgMatrix(seed)
	if err != nil {
		return nil, err
	}
	tmp := make([]byte, 0, pp.paramMa*pp.paramLa*pp.paramD*4)
	for i := 0; i < len(imgM); i++ {
		for j := 0; j < len(imgM[i].polyNTTs); j++ {
			for k := 0; k < len(imgM[i].polyNTTs[j].coeffs); k++ {
				seed = append(seed, byte(imgM[i].polyNTTs[j].coeffs[k]>>0))
				seed = append(seed, byte(imgM[i].polyNTTs[j].coeffs[k]>>8))
				seed = append(seed, byte(imgM[i].polyNTTs[j].coeffs[k]>>16))
				seed = append(seed, byte(imgM[i].polyNTTs[j].coeffs[k]>>24))
			}

		}
	}
	return H(tmp)
}

//	public fun	end

//	well-from check 	begin
func (mpk *MasterPublicKey) WellformCheck(pp *PublicParameter) bool {
	// todo
	return true
}

func (msvk *MasterSecretViewKey) WellformCheck(pp *PublicParameter) bool {
	// todo
	return true
}

func (mssk *MasterSecretSignKey) WellformCheck(pp *PublicParameter) bool {
	// todo
	return true
}

//	well-from check 	end

//	serialize and deSeralize	begin
func (mpk *MasterPublicKey) SerializeSize() uint32 {
	//	todo
	return 1
}

func (mpk *MasterPublicKey) Serialize() []byte {
	//	todo
	return nil
}

func (mpk *MasterPublicKey) Deserialize(mpkSer []byte) error {
	return nil
}

func (msvk *MasterSecretViewKey) SerializeSize() uint32 {
	//	todo
	return 1
}

func (msvk *MasterSecretViewKey) Serialize() []byte {
	//	todo
	return nil
}

func (msvk *MasterSecretViewKey) Deserialize(msvkSer []byte) error {
	return nil
}

func (mssk *MasterSecretSignKey) SerializeSize() uint32 {
	//	todo
	return 1
}

func (mssk *MasterSecretSignKey) Serialize() []byte {
	//	todo
	return nil
}

func (mssk *MasterSecretSignKey) Deserialize(msskSer []byte) error {
	return nil
}

//	serialize and deSeralize	end
