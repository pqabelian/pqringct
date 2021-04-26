package pqringct

const (
	PP_N = 51 //	N defines the value of V by V=2^N - 1
	PP_I = 5  //	PP_I defines the maximum number of consumed coins of a transfer transaction
	PP_J = 5  //	PP_J defines the maximum number of generated coins of a transaction

	PP_d   = 128
	PP_q   = 4294962689 //	q=11111111111111111110111000000001 is a 32-bit prime such that q = 1 mod 512,
	PP_q_m = 2147481344 //	q_m = q/2-1
	// PP_l = 128	//	We use fully-splitting ring, namely l=d, thus we only use d
	PP_k = 4

	PP_k_a    = 10       //	todo:
	PP_l_a    = 10       //	todo:
	PP_eta_a  = 1024 - 1 //	todo:
	PP_beta_a = 2        //	 todo:

	PP_k_c      = 10       //	todo:
	PP_l_c      = 10       //	todo:
	PP_eta_c    = 1024 - 1 //	todo:
	PP_beta_c   = 2        //	 todo:
	PP_eta_c_1  = 1024 - 1 //	todo:
	PP_beta_c_1 = 2        //	 todo:

	PP_m_a   = 1        //	todo:
	PP_eta_f = 1024 - 1 // todo:
)

type PublicParamter struct {
	paramN int //	paramN defines the value of V by V=2^N - 1
	paramI int //	paramI defines the maximum number of consumed coins of a transfer transaction
	paramJ int //	paramJ defines the maximum number of generated coins of a transaction

	paramD  int
	paramQ  int // a 32-bit prime such that q = 1 mod 512,
	paramQm int
	paramK  int

	paramKa    int
	paramLa    int
	paramETAa  int
	paramBETAa int

	paramKc     int
	paramLc     int
	paramETAc   int
	paramBETAc  int
	paramETAc1  int
	paramBETAc1 int

	paramMa   int
	paramETAf int
}

func NewPublicParamter(
	paramN int,
	paramI int,
	paramJ int,
	paramD int,
	paramQ int,
	//paramQm int,
	paramK int,
	paramKa int,
	paramLa int,
	paramETAa int,
	paramBETAa int,
	paramKc int,
	paramLc int,
	paramETAc int,
	paramBETAc int,
	paramETAc1 int,
	paramBETAc1 int,
	paramMa int,
	paramETAf int,
) *PublicParamter {

	res := &PublicParamter{
		paramN: paramN,
		paramI: paramI,
		paramJ: paramJ,
		paramD: paramD,
		paramQ: paramQ,
		//paramQm:    paramQm,
		paramK:     paramK,
		paramKa:    paramKa,
		paramLa:    paramLa,
		paramETAa:  paramETAa,
		paramBETAa: paramBETAa,
		paramKc:    paramKc,
		paramLc:    paramLc,
		paramETAc:  paramETAc,
		paramBETAc: paramBETAc,
		paramMa:    paramMa,
		paramETAf:  paramETAf,
	}
	res.paramQm = res.paramQ >> 1
	return res
}

var DefaultPP *PublicParamter = NewPublicParamter(
	51,
	5,
	5,

	128,
	4294962689,
	4,

	10,
	10,
	1024-1,
	2,

	10,
	10,
	1024-1,
	2,

	1024-1,
	2,

	1,
	1024-1,
)

// PQRingCT TODO: optimize the interface using array?
type PQRingCT interface {
	MasterKeyGen(seed []byte) (*MasterPubKey, *MasterSecretViewKey, *MasterSecretSignKey)
	CoinbaseTxGen(vin int32, txos []*TxOutputDesc) *CoinbaseTx //(dpk *DerivedPubKey,commit []byte,vc []byte)
	CoinbaseTxVerify(tx *CoinbaseTx) bool
	TXOCoinReceive(dpk *DerivedPubKey, commitment []byte, vc []byte, mpk *MasterPubKey, key *MasterSecretViewKey) (bool, int32)
	TransferTXGen([]*TxInputDesc, []*TxOutputDesc) *TransferTx
	TransferTXVerify(tx *TransferTx) bool
}

type PolyVecA struct {
	vec [PP_l_a]Poly
}

type PolyVecC struct {
	vec [PP_l_c]Poly
}

type PolyVecANTT struct {
	vec [PP_l_a]PolyNTT
}

type PolyVecCNTT struct {
	vec [PP_l_c]PolyNTT
}

type PubParams struct {
	A [PP_k_a]PolyVecANTT
	B [PP_k_c]PolyVecCNTT
	C [PP_I + PP_J + 7]PolyVecCNTT //	C[0] = h, C[1]=h_1, ..., C[PP_I+PP_J+6]=h_{PP_I+PP_J+6}
}
